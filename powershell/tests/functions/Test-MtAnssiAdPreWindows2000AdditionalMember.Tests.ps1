BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-056.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPreWindows2000AdditionalMember' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPreWindows2000AdditionalMember {
        InModuleScope Maester { Test-MtAnssiAdPreWindows2000AdditionalMember }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    $script:fsp = 'CN={0},CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
    $script:authenticatedDn = $script:fsp -f 'S-1-5-11'
    $script:everyoneDn = $script:fsp -f 'S-1-1-0'
    $script:anonymousDn = $script:fsp -f 'S-1-5-7'

    function Use-Group {
        param([AllowEmptyCollection()] [string[]] $Member = @())
        $result = [PSCustomObject]@{
            Group  = [PSCustomObject]@{ Name = 'Pre-Windows 2000 Compatible Access' }
            Member = $Member
        }
        $state = [PSCustomObject]@{
            Groups           = @([PSCustomObject]@{ Name = 'G1' })
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        Mock Get-MtAnssiAdGroupMemberDn -ModuleName Maester -MockWith (
            { $result }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdPreWindows2000AdditionalMember' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when the group only has Authenticated Users' {
            Use-Group -Member @($authenticatedDn)

            Test-MtAnssiAdPreWindows2000AdditionalMember | Should -Be $true
        }

        It 'passes when the group is empty' {
            Use-Group -Member @()

            Test-MtAnssiAdPreWindows2000AdditionalMember | Should -Be $true
        }

        It 'fails when Everyone is a member' {
            Use-Group -Member @($authenticatedDn, $everyoneDn)

            Test-MtAnssiAdPreWindows2000AdditionalMember | Should -Be $false
        }

        It 'fails when Anonymous Logon is a member' {
            Use-Group -Member @($anonymousDn)

            Test-MtAnssiAdPreWindows2000AdditionalMember | Should -Be $false
        }

        It 'fails when a domain account is a member, such as a certification authority' {
            Use-Group -Member @($authenticatedDn, 'CN=CA1,OU=Servers,DC=contoso,DC=com')

            Test-MtAnssiAdPreWindows2000AdditionalMember | Should -Be $false
        }

        It 'fails when Authenticated Users is missing and nothing else is there but a user' {
            Use-Group -Member @('CN=Bob,OU=Users,DC=contoso,DC=com')

            Test-MtAnssiAdPreWindows2000AdditionalMember | Should -Be $false
        }
    }

    Context 'result text' {
        It 'states the group is clean when the test passes' {
            Use-Group -Member @($authenticatedDn)

            $null = Test-MtAnssiAdPreWindows2000AdditionalMember

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'no member besides Authenticated Users'
            }
        }

        It 'counts and lists only the additional members, sorted by name' {
            Use-Group -Member @(
                'CN=Zed,OU=Users,DC=contoso,DC=com'
                $authenticatedDn
                $everyoneDn
                'CN=Abe,OU=Users,DC=contoso,DC=com'
            )

            $null = Test-MtAnssiAdPreWindows2000AdditionalMember

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '3 member\(s\) besides Authenticated Users' -and
                $text -match '(?s)CN=Abe,.*CN=S-1-1-0,.*CN=Zed,' -and
                $text -notmatch 'S-1-5-11'
            }
        }

        It 'shows the identity and the SID of well-known members' {
            Use-Group -Member @($everyoneDn, $anonymousDn, 'CN=CA1,DC=contoso,DC=com')

            $null = Test-MtAnssiAdPreWindows2000AdditionalMember

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match 'Everyone \| S-1-1-0 \|' -and
                $text -match 'Anonymous Logon \| S-1-5-7 \|' -and
                $text -match 'Account or group of the domain \|'
            }
        }

        It 'escapes markdown in the member name' {
            Use-Group -Member @('CN=[click](https://evil.example)|x,DC=contoso,DC=com')

            $null = Test-MtAnssiAdPreWindows2000AdditionalMember

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Groups category' {
            Use-Group

            $null = Test-MtAnssiAdPreWindows2000AdditionalMember

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Groups' }
        }
    }

    Context 'member read' {
        It 'reads the members of S-1-5-32-554 with the collected groups and evidence' {
            Use-Group

            $null = Test-MtAnssiAdPreWindows2000AdditionalMember

            Should -Invoke Get-MtAnssiAdGroupMemberDn -ModuleName Maester -Times 1 `
                -Exactly -ParameterFilter {
                @($Group).Count -eq 1 -and $Group[0].Name -eq 'G1' -and
                $Sid -eq 'S-1-5-32-554' -and $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the group is not in the collected data' {
            Use-Group
            Mock Get-MtAnssiAdGroupMemberDn -ModuleName Maester -MockWith { $null }

            Test-MtAnssiAdPreWindows2000AdditionalMember | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'S-1-5-32-554'
            }
        }

        It 'lets the exception reach the engine when the members cannot be read' {
            Use-Group
            Mock Get-MtAnssiAdGroupMemberDn -ModuleName Maester `
                -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdPreWindows2000AdditionalMember } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdPreWindows2000AdditionalMember } | Should -Throw 'LDAP bind failed'

        }
    }
}
