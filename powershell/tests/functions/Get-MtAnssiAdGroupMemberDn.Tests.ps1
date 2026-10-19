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

    $script:groupDn = 'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=contoso,DC=com'
    $script:evidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }

    function Get-GroupFixture {
        param([string] $Sid = 'S-1-5-32-554', [string] $Dn = $script:groupDn)
        [PSCustomObject]@{
            DistinguishedName = $Dn
            Name              = 'Group'
            Sid               = [PSCustomObject]@{ Value = $Sid }
        }
    }

    function Use-Ldap {
        param([AllowEmptyCollection()] [string[]] $Member = @())
        $members = $Member
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Get-MtLdapRangedValue -ModuleName Maester -MockWith ({ $members }.GetNewClosure())
    }

    function Invoke-Helper {
        param([AllowNull()] [object[]] $Group = @(Get-GroupFixture), [string] $Sid = 'S-1-5-32-554')
        $parameters = @{ Group = $Group; Sid = $Sid; Evidence = $script:evidence }
        InModuleScope Maester -Parameters $parameters {
            param($Group, $Sid, $Evidence)
            Get-MtAnssiAdGroupMemberDn -Group $Group -Sid $Sid -ProtocolEvidence $Evidence
        }
    }
}

Describe 'Get-MtAnssiAdGroupMemberDn' {
    It 'returns the group and its member names' {
        Use-Ldap -Member @('CN=a,DC=x', 'CN=b,DC=x')

        $result = Invoke-Helper

        $result.Group.DistinguishedName | Should -Be $groupDn
        @($result.Member) | Should -Be @('CN=a,DC=x', 'CN=b,DC=x')
    }

    It 'returns an empty member list for an empty group' {
        Use-Ldap -Member @()

        $result = Invoke-Helper

        $null -ne $result | Should -Be $true
        @($result.Member).Count | Should -Be 0
    }

    It 'finds the group by its SID, not by its name' {
        Use-Ldap -Member @('CN=a,DC=x')

        $null = Invoke-Helper -Group @(
            Get-GroupFixture -Sid 'S-1-5-32-545' -Dn 'CN=Users,CN=Builtin,DC=contoso,DC=com'
            Get-GroupFixture -Dn 'CN=Vorwindows,CN=Builtin,DC=contoso,DC=com'
        )

        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $DistinguishedName -eq 'CN=Vorwindows,CN=Builtin,DC=contoso,DC=com' -and
            $AttributeName -eq 'member' -and $Connection -is [TrackedLdapConnection]
        }
    }

    It 'finds a domain group by the SID it is given' {
        Use-Ldap -Member @('CN=a,DC=x')
        $groups = @(
            (Get-GroupFixture -Dn 'CN=Pre2000,CN=Builtin,DC=contoso,DC=com')
            (Get-GroupFixture -Sid 'S-1-5-21-1-2-3-571' `
                -Dn 'CN=Allowed RODC,CN=Users,DC=contoso,DC=com')
        )

        $result = Invoke-Helper -Group $groups -Sid 'S-1-5-21-1-2-3-571'

        $result.Group.DistinguishedName | Should -Be 'CN=Allowed RODC,CN=Users,DC=contoso,DC=com'
        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $DistinguishedName -eq 'CN=Allowed RODC,CN=Users,DC=contoso,DC=com' }
    }

    It 'returns null without reading when the group is not collected' {
        Use-Ldap -Member @('CN=a,DC=x')

        Invoke-Helper -Group @(Get-GroupFixture -Sid 'S-1-5-32-545') | Should -BeNullOrEmpty

        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 0 -Exactly
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 0 -Exactly
    }

    It 'returns null when no groups were collected' {
        Use-Ldap

        Invoke-Helper -Group $null | Should -BeNullOrEmpty
    }

    It 'disposes the connection after a successful read' {
        Use-Ldap -Member @('CN=a,DC=x')

        $null = Invoke-Helper

        $script:connection.Disposed | Should -Be $true
    }

    It 'throws when the members cannot be read, and disposes the connection' {
        Use-Ldap
        Mock Get-MtLdapRangedValue -ModuleName Maester -MockWith { throw 'LDAP search failed' }

        { Invoke-Helper } | Should -Throw '*LDAP search failed*'

        $script:connection.Disposed | Should -Be $true
    }

    It 'throws when the connection cannot be created' {
        Use-Ldap
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith { throw 'no route' }

        { Invoke-Helper } | Should -Throw '*no route*'
    }
}
