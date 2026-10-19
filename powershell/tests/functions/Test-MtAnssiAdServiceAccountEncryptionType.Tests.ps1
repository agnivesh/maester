BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-057.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdServiceAccountEncryptionType' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdServiceAccountEncryptionType {
        InModuleScope Maester { Test-MtAnssiAdServiceAccountEncryptionType }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-UserFixture {
        param(
            [string] $Name = 'svc',
            [AllowNull()] [object] $Types = 28,
            [object] $Spn = @('HTTP/app.contoso.com'),
            [bool] $Enabled = $true,
            [AllowNull()] [object] $LastLogon = $null
        )
        [PSCustomObject]@{
            DistinguishedName        = "CN=$Name,OU=Service,DC=contoso,DC=com"
            Name                     = $Name
            Enabled                  = $Enabled
            ServicePrincipalName     = $Spn
            SupportedEncryptionTypes = $Types
            LastLogonDate            = $LastLogon
        }
    }

    function Use-Ad {
        param([AllowNull()] [object[]] $User = @())
        $state = [PSCustomObject]@{ Users = $User }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdServiceAccountEncryptionType' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes for <Types>, which declares AES' -ForEach @(
            @{ Types = 28 }
            @{ Types = 24 }
            @{ Types = 16 }
            @{ Types = 8 }
            @{ Types = 56 }
        ) {
            Use-Ad -User @(Get-UserFixture -Types $Types)

            Test-MtAnssiAdServiceAccountEncryptionType | Should -Be $true
        }

        It 'fails for <Types>, which declares no AES ticket encryption' -ForEach @(
            @{ Types = $null }
            @{ Types = 0 }
            @{ Types = 4 }
            @{ Types = 1 }
            @{ Types = 3 }
            @{ Types = 36 }
            @{ Types = 32 }
        ) {
            Use-Ad -User @(Get-UserFixture -Types $Types)

            Test-MtAnssiAdServiceAccountEncryptionType | Should -Be $false
        }

        It 'fails when one of several accounts has no AES' {
            Use-Ad -User @(
                (Get-UserFixture -Name 'good' -Types 28)
                (Get-UserFixture -Name 'bad' -Types 4)
            )

            Test-MtAnssiAdServiceAccountEncryptionType | Should -Be $false
        }

        It 'ignores a disabled account' {
            Use-Ad -User @(Get-UserFixture -Types 4 -Enabled $false)

            Test-MtAnssiAdServiceAccountEncryptionType | Should -Be $true
        }

        It 'ignores an account without a service principal name' {
            Use-Ad -User @(
                (Get-UserFixture -Name 'a' -Types 4 -Spn @())
                (Get-UserFixture -Name 'b' -Types 4 -Spn $null)
            )

            Test-MtAnssiAdServiceAccountEncryptionType | Should -Be $true
        }

        It 'evaluates an account whose SPN is a single string' {
            Use-Ad -User @(Get-UserFixture -Types 4 -Spn 'HTTP/app')

            Test-MtAnssiAdServiceAccountEncryptionType | Should -Be $false
        }
    }

    Context 'result text' {
        It 'counts the service accounts when the test passes' {
            Use-Ad -User @(
                (Get-UserFixture -Name 'a' -Types 28)
                (Get-UserFixture -Name 'b' -Types 24)
                (Get-UserFixture -Name 'plain' -Types 4 -Spn @())
            )

            $null = Test-MtAnssiAdServiceAccountEncryptionType

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 enabled user accounts with a service principal name'
            }
        }

        It 'says so when no enabled account has a service principal name' {
            Use-Ad -User @(Get-UserFixture -Spn @())

            $null = Test-MtAnssiAdServiceAccountEncryptionType

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No enabled user account has a service principal name'
            }
        }

        It 'lists the accounts without AES by name with the decoded value and last logon' {
            Use-Ad -User @(
                (Get-UserFixture -Name 'zed' -Types 4 -Spn @('MSSQL/db1', 'MSSQL/db2') `
                    -LastLogon ([datetime]'2026-03-04'))
                (Get-UserFixture -Name 'ok' -Types 28)
                (Get-UserFixture -Name 'abe' -Types $null)
            )

            $null = Test-MtAnssiAdServiceAccountEncryptionType

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^2 of 3 enabled user accounts with a service principal name' -and
                $text -match ('(?s)abe \| HTTP/app\.contoso\.com \| Not set \| Never \|.*' +
                    'zed \| MSSQL/db1 \| RC4 \(0x4\) \| 2026-03-04 \|') -and
                $text -notmatch '\| ok \|' -and $text -notmatch 'MSSQL/db2'
            }
        }

        It 'escapes markdown in the account name' {
            Use-Ad -User @(Get-UserFixture -Name '[click](https://evil.example)|x' -Types 4)

            $null = Test-MtAnssiAdServiceAccountEncryptionType

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Users category' {
            Use-Ad -User @(Get-UserFixture)

            $null = Test-MtAnssiAdServiceAccountEncryptionType

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Users' }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when there are no users' {
            Use-Ad -User @()

            Test-MtAnssiAdServiceAccountEncryptionType | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match 'msDS-SupportedEncryptionTypes'
            }
        }

        It 'is skipped when the users do not carry the attribute' {
            $user = [PSCustomObject]@{
                Name = 'svc'; Enabled = $true; ServicePrincipalName = @('HTTP/app')
            }
            Use-Ad -User @($user)

            Test-MtAnssiAdServiceAccountEncryptionType | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdServiceAccountEncryptionType } | Should -Throw 'LDAP bind failed'

        }
    }
}
