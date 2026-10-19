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
        param([string] $Name, [string] $Sid, [AllowNull()] [object] $PrimaryGroupId = $null)
        [PSCustomObject]@{
            DistinguishedName = Get-Dn -Name $Name
            Name              = $Name
            Sid               = [PSCustomObject]@{ Value = $Sid }
            PrimaryGroupId    = $PrimaryGroupId
        }
    }

    function Get-BaseGroup {
        @(
            Get-ObjectFixture -Name 'Administrators' -Sid 'S-1-5-32-544'
            Get-ObjectFixture -Name 'Domain Admins' -Sid "$script:domainSid-512"
        )
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

    function Get-Privileged {
        param(
            [object[]] $User = @(),
            [object[]] $Computer = @(),
            [object[]] $Group = (Get-BaseGroup),
            [string] $Server = 'dc1'
        )
        $parameters = @{
            User = $User; Computer = $Computer; Group = $Group; Sid = $script:domainSid
            Evidence = [PSCustomObject]@{ ResolvedServer = $Server }
        }
        InModuleScope Maester -Parameters $parameters {
            param($User, $Computer, $Group, $Sid, $Evidence)
            Get-MtAnssiAdPrivilegedAccount -User $User -Computer $Computer -Group $Group `
                -DomainSid $Sid -ProtocolEvidence $Evidence
        }
    }
}

Describe 'Get-MtAnssiAdPrivilegedAccount' {
    BeforeEach {
        Clear-MtADCache
    }

    Context 'protected groups' {
        It 'treats the members of <Name> (<Sid>) as privileged' -ForEach @(
            @{ Name = 'Administrators'; Sid = 'S-1-5-32-544' }
            @{ Name = 'Account Operators'; Sid = 'S-1-5-32-548' }
            @{ Name = 'Server Operators'; Sid = 'S-1-5-32-549' }
            @{ Name = 'Print Operators'; Sid = 'S-1-5-32-550' }
            @{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551' }
            @{ Name = 'Replicator'; Sid = 'S-1-5-32-552' }
            @{ Name = 'Domain Admins'; Sid = 'S-1-5-21-1-2-3-512' }
            @{ Name = 'Domain Controllers'; Sid = 'S-1-5-21-1-2-3-516' }
            @{ Name = 'Schema Admins'; Sid = 'S-1-5-21-1-2-3-518' }
            @{ Name = 'Enterprise Admins'; Sid = 'S-1-5-21-1-2-3-519' }
            @{ Name = 'Read-only Domain Controllers'; Sid = 'S-1-5-21-1-2-3-521' }
            @{ Name = 'Key Admins'; Sid = 'S-1-5-21-1-2-3-526' }
            @{ Name = 'Enterprise Key Admins'; Sid = 'S-1-5-21-1-2-3-527' }
        ) {
            $groups = @(Get-BaseGroup | Where-Object { $_.Sid.Value -ne $Sid }) +
                @(Get-ObjectFixture -Name $Name -Sid $Sid)
            $alice = Get-ObjectFixture -Name 'alice' -Sid "$domainSid-1105"
            Use-Ldap -Directory @{ (Get-Dn $Name) = @((Get-Dn 'alice')) }

            $result = Get-Privileged -User @($alice) -Group $groups

            @($result.Account).Count | Should -Be 1
            @($result.Account[0].Group) | Should -Be @($Name)
        }

        It 'does not treat the members of <Name> (<Sid>) as privileged' -ForEach @(
            @{ Name = 'Domain Users'; Sid = 'S-1-5-21-1-2-3-513' }
            @{ Name = 'Cert Publishers'; Sid = 'S-1-5-21-1-2-3-517' }
            @{ Name = 'Group Policy Creator Owners'; Sid = 'S-1-5-21-1-2-3-520' }
            @{ Name = 'Enterprise Read-only Domain Controllers'; Sid = 'S-1-5-21-1-2-3-498' }
            @{ Name = 'DnsAdmins'; Sid = 'S-1-5-21-1-2-3-1101' }
            @{ Name = 'Remote Desktop Users'; Sid = 'S-1-5-32-555' }
        ) {
            $groups = @(Get-BaseGroup) + @(Get-ObjectFixture -Name $Name -Sid $Sid)
            $alice = Get-ObjectFixture -Name 'alice' -Sid "$domainSid-1105"
            Use-Ldap -Directory @{ (Get-Dn $Name) = @((Get-Dn 'alice')) }

            $result = Get-Privileged -User @($alice) -Group $groups

            @($result.Account).Count | Should -Be 0
        }

        It 'treats a member through a nested group, a primary group and RID 500 as privileged' {
            $groups = @(Get-BaseGroup) + @(Get-ObjectFixture -Name 'Tier0' -Sid "$domainSid-1200")
            $users = @(
                Get-ObjectFixture -Name 'alice' -Sid "$domainSid-1105"
                Get-ObjectFixture -Name 'bob' -Sid "$domainSid-1106" -PrimaryGroupId 512
                Get-ObjectFixture -Name 'Administrator' -Sid "$domainSid-500"
                Get-ObjectFixture -Name 'carol' -Sid "$domainSid-1107" -PrimaryGroupId 513
            )
            Use-Ldap -Directory @{
                (Get-Dn 'Administrators') = @((Get-Dn 'Tier0'))
                (Get-Dn 'Tier0')          = @((Get-Dn 'alice'))
            }

            $result = Get-Privileged -User $users -Group $groups

            $names = @($result.Account | ForEach-Object { $_.Item.Name } | Sort-Object)
            $names | Should -Be @('Administrator', 'alice', 'bob')
        }

        It 'returns the members it cannot resolve' {
            $foreign = 'CN=S-1-5-21-9-9-9-519,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
            Use-Ldap -Directory @{ (Get-Dn 'Administrators') = @($foreign) }

            $result = Get-Privileged

            @($result.Unresolved).Count | Should -Be 1
            $result.Unresolved[0].DistinguishedName | Should -BeExactly $foreign
        }
    }

    Context 'missing data' {
        It 'throws without reading when <Name> is not in the collected groups' -ForEach @(
            @{ Name = 'Administrators'; Sid = 'S-1-5-32-544' }
            @{ Name = 'Domain Admins'; Sid = 'S-1-5-21-1-2-3-512' }
        ) {
            Use-Ldap -Directory @{}
            $groups = @(Get-BaseGroup | Where-Object { $_.Sid.Value -ne $Sid })

            { Get-Privileged -Group $groups } | Should -Throw -ExpectedMessage "*$Sid*"

            Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 0 -Exactly
        }

        It 'throws when a member list cannot be read, and reads again on the next call' {
            $failing = Get-Dn 'Domain Admins'
            Use-Ldap -Directory @{ (Get-Dn 'Administrators') = @() } -FailOn $failing

            { Get-Privileged } | Should -Throw -ExpectedMessage 'LDAP search failed'

            Use-Ldap -Directory @{ (Get-Dn 'Administrators') = @(); (Get-Dn 'Domain Admins') = @() }
            $null = Get-Privileged
            Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 2 -Exactly `
                -ParameterFilter { $DistinguishedName -eq (Get-Dn 'Domain Admins') }
            Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 3 -Exactly
        }
    }

    Context 'session cache' {
        It 'reads the member lists once per server for the session' {
            Use-Ldap -Directory @{ (Get-Dn 'Administrators') = @(); (Get-Dn 'Domain Admins') = @() }

            $null = Get-Privileged
            $null = Get-Privileged

            Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 2 -Exactly
        }

        It 'reads the member lists again for another server' {
            Use-Ldap -Directory @{ (Get-Dn 'Administrators') = @(); (Get-Dn 'Domain Admins') = @() }

            $null = Get-Privileged -Server 'dc1'
            $null = Get-Privileged -Server 'dc2'

            Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 4 -Exactly
        }

        It 'reads the member lists again after Clear-MtADCache' {
            Use-Ldap -Directory @{ (Get-Dn 'Administrators') = @(); (Get-Dn 'Domain Admins') = @() }

            $null = Get-Privileged
            Clear-MtADCache
            $null = Get-Privileged

            Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 4 -Exactly
        }
    }
}
