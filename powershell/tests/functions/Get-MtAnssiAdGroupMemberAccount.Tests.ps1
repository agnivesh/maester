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

    function Get-Dn {
        param([string] $Name)
        "CN=$Name,DC=contoso,DC=com"
    }

    function Get-ObjectFixture {
        param([string] $Name, [string] $Rid, [AllowNull()] [object] $PrimaryGroupId = $null)
        [PSCustomObject]@{
            DistinguishedName = Get-Dn -Name $Name
            Name              = $Name
            Sid               = [PSCustomObject]@{ Value = "$script:domainSid-$Rid" }
            PrimaryGroupId    = $PrimaryGroupId
        }
    }

    function Use-Ldap {
        param([hashtable] $Directory, [string] $FailOn = '')
        $script:directory = $Directory
        $script:failDn = $FailOn
        $tracked = [TrackedLdapConnection]::new()
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Get-MtLdapRangedValue -ModuleName Maester -MockWith {
            if ($DistinguishedName -eq $script:failDn) { throw 'LDAP search failed' }
            foreach ($memberDn in $script:directory[$DistinguishedName]) { $memberDn }
        }
    }

    function Get-MemberAccount {
        param([object[]] $User = @(), [object[]] $Group = @(), [string] $Rid = '525')
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID = [PSCustomObject]@{ Value = $script:domainSid }
            }
            Users            = $User
            Computers        = @(Get-ObjectFixture -Name 'PC1' -Rid '1300' -PrimaryGroupId 525)
            Groups           = $Group
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        InModuleScope Maester -Parameters @{ State = $state; Sid = "$script:domainSid-$Rid" } {
            param($State, $Sid)
            Get-MtAnssiAdGroupMemberAccount -AdState $State -GroupSid $Sid
        }
    }

    $script:groups = @(
        Get-ObjectFixture -Name 'Protected Users' -Rid '525'
        Get-ObjectFixture -Name 'Tier0' -Rid '1200'
    )
    $script:users = @(
        Get-ObjectFixture -Name 'alice' -Rid '1105'
        Get-ObjectFixture -Name 'bob' -Rid '1106'
        Get-ObjectFixture -Name 'carol' -Rid '1107' -PrimaryGroupId 525
    )
}

Describe 'Get-MtAnssiAdGroupMemberAccount' {
    BeforeEach {
        Clear-MtADCache
    }

    It 'returns the group and its direct, nested and primary-group member accounts' {
        Use-Ldap -Directory @{
            (Get-Dn 'Protected Users') = @((Get-Dn 'alice'), (Get-Dn 'Tier0'), 'CN=S-1-5-11,CN=FSP')
            (Get-Dn 'Tier0')           = @((Get-Dn 'bob'))
        }

        $result = Get-MemberAccount -User $users -Group $groups

        $result.Group.Name | Should -BeExactly 'Protected Users'
        @($result.MemberDn | Sort-Object) |
            Should -Be @((Get-Dn 'alice'), (Get-Dn 'bob'), (Get-Dn 'carol'), (Get-Dn 'PC1'))
        @($result.NestedGroup) -join ';' | Should -BeExactly (Get-Dn 'Tier0')
        @($result.Unresolved) -join ';' | Should -BeExactly 'CN=S-1-5-11,CN=FSP'
    }

    It 'finds a member name without regard to case' {
        Use-Ldap -Directory @{ (Get-Dn 'Protected Users') = @((Get-Dn 'alice')) }

        $result = Get-MemberAccount -User $users -Group $groups

        $result.MemberDn.Contains('cn=ALICE,dc=contoso,dc=com') | Should -Be $true
    }

    It 'returns no group and no member, without reading, when the group is not collected' {
        Use-Ldap -Directory @{}

        $result = Get-MemberAccount -User $users -Group $groups -Rid '999'

        $null -eq $result.Group | Should -Be $true
        $result.MemberDn.Count | Should -Be 0
        @($result.NestedGroup).Count | Should -Be 0
        @($result.Unresolved).Count | Should -Be 0
        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 0 -Exactly
    }

    It 'reads the member lists once for the session' {
        Use-Ldap -Directory @{ (Get-Dn 'Protected Users') = @((Get-Dn 'alice')) }

        $null = Get-MemberAccount -User $users -Group $groups
        $null = Get-MemberAccount -User $users -Group $groups

        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 1 -Exactly
    }

    It 'throws when a member list cannot be read' {
        Use-Ldap -Directory @{} -FailOn (Get-Dn 'Protected Users')

        { Get-MemberAccount -User $users -Group $groups } |
            Should -Throw -ExpectedMessage 'LDAP search failed'
    }
}
