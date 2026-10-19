BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-039.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPreWindows2000AnonymousAccess' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPreWindows2000AnonymousAccess {
        InModuleScope Maester { Test-MtAnssiAdPreWindows2000AnonymousAccess }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

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
    $script:anonymousDn = 'CN=S-1-5-7,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
    $script:authenticatedDn = 'CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
    $script:everyoneDn = 'CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'

    function Get-GroupFixture {
        param([string] $Sid = 'S-1-5-32-554', [string] $Dn = $script:groupDn)
        [PSCustomObject]@{
            DistinguishedName = $Dn
            Name              = 'Pre-Windows 2000 Compatible Access'
            Sid               = [PSCustomObject]@{ Value = $Sid }
        }
    }

    function Use-Ad {
        param(
            [object[]] $Group = @(Get-GroupFixture),
            [AllowEmptyCollection()] [string[]] $Member = @()
        )
        $state = [PSCustomObject]@{
            Groups           = $Group
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        $members = $Member
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Get-MtLdapRangedValue -ModuleName Maester -MockWith ({ $members }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdPreWindows2000AnonymousAccess' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'fails when Anonymous Logon is a member' {
            Use-Ad -Member @($authenticatedDn, $anonymousDn)

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $false
        }

        It 'fails when Anonymous Logon is the only member' {
            Use-Ad -Member @($anonymousDn)

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $false
        }

        It 'matches the member DN case-insensitively' {
            Use-Ad -Member @($anonymousDn.ToLowerInvariant())

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $false
        }

        It 'passes when the group only has Authenticated Users' {
            Use-Ad -Member @($authenticatedDn)

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $true
        }

        It 'passes when the group is empty' {
            Use-Ad -Member @()

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $true
        }

        It 'passes with Everyone as a member, which is not this finding' {
            Use-Ad -Member @($everyoneDn)

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $true
        }

        It 'does not match a SID that only starts like Anonymous Logon' {
            Use-Ad -Member @('CN=S-1-5-70,CN=ForeignSecurityPrincipals,DC=contoso,DC=com')

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $true
        }

        It 'does not match a user that is merely named like the SID' {
            Use-Ad -Member @('CN=S-1-5-7,CN=Users,DC=contoso,DC=com')

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $true
        }

        It 'does not match a DN that only contains the Anonymous Logon principal' {
            Use-Ad -Member @(
                'CN=x,CN=S-1-5-7,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
                'OU=CN=S-1-5-7,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
            )

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $true
        }

        It 'finds the group by its SID, not by its name' {
            Use-Ad -Group @(
                Get-GroupFixture -Sid 'S-1-5-32-545' -Dn 'CN=Users,CN=Builtin,DC=contoso,DC=com'
                Get-GroupFixture -Dn 'CN=Vorwindows,CN=Builtin,DC=contoso,DC=com'
            ) -Member @($anonymousDn)

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -Be $false

            Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DistinguishedName -eq 'CN=Vorwindows,CN=Builtin,DC=contoso,DC=com' -and
                $AttributeName -eq 'member'
            }
        }
    }

    Context 'result text' {
        It 'states the group is clean when the test passes' {
            Use-Ad -Member @($authenticatedDn)

            $null = Test-MtAnssiAdPreWindows2000AnonymousAccess

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'does not include Anonymous Logon'
            }
        }

        It 'lists the Anonymous Logon member and none of the others' {
            Use-Ad -Member @($authenticatedDn, $anonymousDn)

            $null = Test-MtAnssiAdPreWindows2000AnonymousAccess

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'includes Anonymous Logon' -and
                ($Result -replace '\\', '') -match 'CN=S-1-5-7,CN=ForeignSecurityPrincipals' -and
                $Result -notmatch 'S-1-5-11'
            }
        }
    }

    Context 'connection' {
        It 'reads the members of the group through the connection and disposes it' {
            Use-Ad -Member @($authenticatedDn)

            $null = Test-MtAnssiAdPreWindows2000AnonymousAccess

            Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Connection -is [TrackedLdapConnection] }
            $script:connection.Disposed | Should -Be $true
        }

        It 'disposes the connection when the members cannot be read' {
            Use-Ad
            Mock Get-MtLdapRangedValue -ModuleName Maester -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdPreWindows2000AnonymousAccess } | Should -Throw 'LDAP search failed'

            $script:connection.Disposed | Should -Be $true
        }
    }

    Context 'data requested' {
        It 'reads the Groups category' {
            Use-Ad

            $null = Test-MtAnssiAdPreWindows2000AnonymousAccess

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Groups' }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the group is not in the collected data' {
            Use-Ad -Group @(Get-GroupFixture -Sid 'S-1-5-32-545')

            Test-MtAnssiAdPreWindows2000AnonymousAccess | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'S-1-5-32-554'
            }
            Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 0 -Exactly
        }

        It 'lets the exception reach the engine when the members cannot be read' {
            Use-Ad -Member @($anonymousDn)
            Mock Get-MtLdapRangedValue -ModuleName Maester -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdPreWindows2000AnonymousAccess } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when the connection cannot be created' {
            Use-Ad
            Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith { throw 'no route' }

            { Test-MtAnssiAdPreWindows2000AnonymousAccess } | Should -Throw 'no route'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdPreWindows2000AnonymousAccess } | Should -Throw 'LDAP bind failed'

        }
    }
}
