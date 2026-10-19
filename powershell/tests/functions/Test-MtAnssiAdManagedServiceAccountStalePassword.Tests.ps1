BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-048.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdManagedServiceAccountStalePassword' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdManagedServiceAccountStalePassword {
        InModuleScope Maester { Test-MtAnssiAdManagedServiceAccountStalePassword }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    $script:now = [datetime]::SpecifyKind([datetime]'2026-06-01T00:00:00', 'Utc')
    $script:cutoff = $script:now.AddDays(-90)
    $script:gmsa = @('top', 'person', 'organizationalPerson', 'user', 'computer',
        'msDS-GroupManagedServiceAccount')
    $script:msa = @('top', 'person', 'organizationalPerson', 'user', 'computer',
        'msDS-ManagedServiceAccount')
    $script:plain = @('top', 'person', 'organizationalPerson', 'user', 'computer')

    function Get-AccountFixture {
        param(
            [string] $Name = 'gmsa1$',
            [string[]] $Class = $script:gmsa,
            [AllowNull()] [object] $LastSet = $script:now.AddDays(-10),
            [bool] $Enabled = $true,
            [AllowNull()] [object] $LastLogon = $null,
            [switch] $NoClass
        )
        $account = [ordered]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Name            = $Name
            Enabled         = $Enabled
            PasswordLastSet = $LastSet
            LastLogonDate   = $LastLogon
        }
        if (-not $NoClass) { $account['ObjectClass'] = $Class }
        [PSCustomObject]$account
    }

    function Use-Ad {
        param([AllowNull()] [object[]] $Computer = @())
        $state = [PSCustomObject]@{ Computers = $Computer }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdManagedServiceAccountStalePassword' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
        $fixed = $script:now
        Mock Get-Date -ModuleName Maester -MockWith ({ $fixed }.GetNewClosure())
    }

    Context 'verdict' {
        It 'passes when every managed service account changed its password recently' {
            Use-Ad -Computer @(
                (Get-AccountFixture -Name 'g1$')
                (Get-AccountFixture -Name 'm1$' -Class $msa)
            )

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -Be $true
        }

        It 'fails for a gMSA with an old password' {
            Use-Ad -Computer @(Get-AccountFixture -LastSet $now.AddDays(-120))

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -Be $false
        }

        It 'fails for a standalone MSA with an old password' {
            Use-Ad -Computer @(Get-AccountFixture -Class $msa -LastSet $now.AddDays(-120))

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -Be $false
        }

        It 'fails for an account without a password date' {
            Use-Ad -Computer @(Get-AccountFixture -LastSet $null)

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -Be $false
        }

        It 'passes for a password set exactly 90 days ago' {
            Use-Ad -Computer @(Get-AccountFixture -LastSet $cutoff)

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -Be $true
        }

        It 'fails for a password set one second before the 90 days' {
            Use-Ad -Computer @(Get-AccountFixture -LastSet $cutoff.AddSeconds(-1))

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -Be $false
        }

        It 'ignores a disabled account' {
            Use-Ad -Computer @(Get-AccountFixture -LastSet $now.AddDays(-400) -Enabled $false)

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -Be $true
        }

        It 'ignores an ordinary computer with an old password' {
            Use-Ad -Computer @(
                (Get-AccountFixture -Name 'PC1$' -Class $plain -LastSet $now.AddDays(-400))
                (Get-AccountFixture -Name 'g1$')
            )

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -Be $true
        }
    }

    Context 'result text' {
        It 'says so when the domain has no enabled managed service account' {
            Use-Ad -Computer @(
                (Get-AccountFixture -Name 'PC1$' -Class $plain)
                (Get-AccountFixture -Name 'off$' -Enabled $false)
            )

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'no enabled managed service account'
            }
        }

        It 'counts the enabled accounts when the test passes' {
            Use-Ad -Computer @(
                (Get-AccountFixture -Name 'g1$')
                (Get-AccountFixture -Name 'm1$' -Class $msa)
                (Get-AccountFixture -Name 'off$' -Enabled $false)
            )

            $null = Test-MtAnssiAdManagedServiceAccountStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 enabled managed service accounts changed their password' -and
                $Result -match 'last 90 days'
            }
        }

        It 'lists the stale accounts oldest first with type and dates' {
            Use-Ad -Computer @(
                (Get-AccountFixture -Name 'a-gmsa$' -LastSet ([datetime]'2025-12-01') `
                    -LastLogon ([datetime]'2026-05-30'))
                (Get-AccountFixture -Name 'z-msa$' -Class $msa -LastSet ([datetime]'2025-01-02'))
                (Get-AccountFixture -Name 'fresh$')
                (Get-AccountFixture -Name 'm-none$' -LastSet $null)
            )

            $null = Test-MtAnssiAdManagedServiceAccountStalePassword

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^3 of 4 enabled managed service accounts have not changed' -and
                $text -match '\| contoso\.com \|' -and
                $text -match ('(?s)m-none\$ \| gMSA \| Never \| Never \|.*' +
                    'z-msa\$ \| MSA \| 2025-01-02 \| Never \|.*' +
                    'a-gmsa\$ \| gMSA \| 2025-12-01 \| 2026-05-30 \|') -and
                $text -notmatch 'fresh'
            }
        }

        It 'orders accounts with the same date by name' {
            Use-Ad -Computer @(
                (Get-AccountFixture -Name 'b-none$' -LastSet $null)
                (Get-AccountFixture -Name 'a-none$' -LastSet $null)
            )

            $null = Test-MtAnssiAdManagedServiceAccountStalePassword

            Should -Invoke @detail -ParameterFilter {
                ($Result -replace '\\', '') -match '(?s)a-none\$ \|.*b-none\$ \|'
            }
        }

        It 'escapes markdown in the account name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-AccountFixture -Name $evil -LastSet $null)

            $null = Test-MtAnssiAdManagedServiceAccountStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers category' {
            Use-Ad -Computer @(Get-AccountFixture)

            $null = Test-MtAnssiAdManagedServiceAccountStalePassword

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 1 -and $Categories -contains 'Computers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when there are no computers' {
            Use-Ad -Computer @()

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'object classes'
            }
        }

        It 'is skipped when the computers do not carry their object classes' {
            Use-Ad -Computer @(Get-AccountFixture -NoClass)

            Test-MtAnssiAdManagedServiceAccountStalePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdManagedServiceAccountStalePassword } | Should -Throw 'LDAP bind failed'

        }
    }
}
