BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    if (-not ('TrackedLdapConnection' -as [type])) {
        Add-Type -ReferencedAssemblies 'System.DirectoryServices.Protocols' -TypeDefinition @'
public class TrackedLdapConnection : System.DirectoryServices.Protocols.LdapConnection {
    public bool Disposed;
    public TrackedLdapConnection() : base("localhost") {}
    protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
}
'@
    }

    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:evidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }

    function Get-Dn {
        param([string] $Name)
        "CN=$Name,DC=contoso,DC=com"
    }

    function Get-ObjectFixture {
        param([string] $Name, [string] $Rid)
        [PSCustomObject]@{
            DistinguishedName = Get-Dn -Name $Name
            Name              = $Name
            Sid               = [PSCustomObject]@{ Value = "$script:domainSid-$Rid" }
        }
    }

    $script:groups = @(
        Get-ObjectFixture -Name 'Root' -Rid '512'
        Get-ObjectFixture -Name 'Other' -Rid '544'
        Get-ObjectFixture -Name 'Mid' -Rid '1200'
        Get-ObjectFixture -Name 'Leaf' -Rid '1201'
    )
    $script:users = @(Get-ObjectFixture -Name 'alice' -Rid '1105')

    function Use-Ldap {
        param([hashtable] $Directory, [string] $FailOn = '')
        $script:directory = $Directory
        $script:failDn = $FailOn
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Get-MtLdapRangedValue -ModuleName Maester -MockWith {
            if ($DistinguishedName -eq $script:failDn) { throw 'LDAP search failed' }
            $script:directory[$DistinguishedName]
        }
    }

    function Invoke-Reader {
        param([string[]] $Start, [hashtable] $MemberMap)
        $parameters = @{
            Start = @($Start | ForEach-Object { Get-Dn -Name $_ }); Map = $MemberMap
            Sid = $script:domainSid; User = $script:users; Group = $script:groups
            Evidence = $script:evidence
        }
        InModuleScope Maester -Parameters $parameters {
            param($Start, $Map, $Sid, $User, $Group, $Evidence)
            $index = Get-MtAnssiAdDirectoryIndex -User $User -Group $Group -DomainSid $Sid
            Read-MtAnssiAdGroupMemberMap -GroupDn $Start -Index $index -MemberMap $Map `
                -ProtocolEvidence $Evidence
        }
    }
}

Describe 'Read-MtAnssiAdGroupMemberMap' {
    It 'reads the start groups and the groups nested in them, but not other members' {
        Use-Ldap -Directory @{
            (Get-Dn 'Root') = @((Get-Dn 'Mid'), (Get-Dn 'alice'), 'CN=Far,DC=other,DC=com')
            (Get-Dn 'Mid')  = @((Get-Dn 'Leaf'))
            (Get-Dn 'Leaf') = @()
        }
        $map = @{}

        Invoke-Reader -Start 'Root' -MemberMap $map

        $map.Count | Should -Be 3
        @($map[(Get-Dn 'Root')]).Count | Should -Be 3
        @($map[(Get-Dn 'Mid')]) | Should -Be @((Get-Dn 'Leaf'))
        $map.ContainsKey((Get-Dn 'Leaf')) | Should -Be $true
        @($map[(Get-Dn 'Leaf')]).Count | Should -Be 0
        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 3 -Exactly
    }

    It 'reads the member attribute over one connection and disposes it' {
        Use-Ldap -Directory @{ (Get-Dn 'Root') = @((Get-Dn 'Mid')); (Get-Dn 'Mid') = @() }

        Invoke-Reader -Start 'Root' -MemberMap @{}

        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 2 -Exactly `
            -ParameterFilter {
            $AttributeName -eq 'member' -and $Connection -is [TrackedLdapConnection]
        }
        $script:connection.Disposed | Should -Be $true
    }

    It 'reads every start group' {
        Use-Ldap -Directory @{ (Get-Dn 'Root') = @(); (Get-Dn 'Other') = @() }
        $map = @{}

        Invoke-Reader -Start 'Root', 'Other' -MemberMap $map

        $map.Count | Should -Be 2
    }

    It 'reads each group of a nesting loop once' {
        Use-Ldap -Directory @{
            (Get-Dn 'Root') = @((Get-Dn 'Mid'))
            (Get-Dn 'Mid')  = @((Get-Dn 'Root'))
        }

        Invoke-Reader -Start 'Root' -MemberMap @{}

        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 2 -Exactly
    }

    It 'opens no connection when every group is already known' {
        Use-Ldap -Directory @{}
        $map = @{ (Get-Dn 'Root') = @((Get-Dn 'Mid')); (Get-Dn 'Mid') = @() }

        Invoke-Reader -Start 'Root' -MemberMap $map

        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 0 -Exactly
        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 0 -Exactly
    }

    It 'still reads the nested groups of a group that is already known' {
        Use-Ldap -Directory @{ (Get-Dn 'Mid') = @((Get-Dn 'alice')) }
        $map = @{ (Get-Dn 'Root') = @((Get-Dn 'Mid')) }

        Invoke-Reader -Start 'Root' -MemberMap $map

        @($map[(Get-Dn 'Mid')]) | Should -Be @((Get-Dn 'alice'))
        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $DistinguishedName -eq (Get-Dn 'Mid') }
    }

    It 'throws on a failed read, keeps only complete lists and disposes the connection' {
        Use-Ldap -Directory @{ (Get-Dn 'Root') = @((Get-Dn 'Mid')) } -FailOn (Get-Dn 'Mid')
        $map = @{}

        { Invoke-Reader -Start 'Root' -MemberMap $map } |
            Should -Throw -ExpectedMessage 'LDAP search failed'

        $map.ContainsKey((Get-Dn 'Root')) | Should -Be $true
        $map.ContainsKey((Get-Dn 'Mid')) | Should -Be $false
        $script:connection.Disposed | Should -Be $true
    }
}
