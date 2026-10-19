BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-019.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDcStalePassword' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDcStalePassword {
        InModuleScope Maester { Test-MtAnssiAdDcStalePassword }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-ComputerFixture {
        param(
            [string] $Name = 'DC1',
            [int] $PrimaryGroupId = 516,
            [AllowNull()] [Nullable[int]] $PasswordDaysAgo = 10,
            [AllowNull()] [Nullable[bool]] $Enabled = $true
        )
        $passwordLastSet = $null
        if ($null -ne $PasswordDaysAgo) {
            $passwordLastSet = (Get-Date).ToUniversalTime().AddDays(-$PasswordDaysAgo)
        }
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            Name              = $Name
            PrimaryGroupId    = $PrimaryGroupId
            Enabled           = $Enabled
            PasswordLastSet   = $passwordLastSet
        }
    }

    function Use-Ad {
        param([object[]] $Computer)
        $state = [PSCustomObject]@{ Computers = $Computer; DomainControllers = @() }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDcStalePassword' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'age of the password' {
        It '<Name>' -ForEach @(
            @{ Name = 'passes with the default change of 30 days'; DaysAgo = 30; Expected = $true }
            @{ Name = 'passes just under 45 days'; DaysAgo = 44; Expected = $true }
            @{ Name = 'fails just over 45 days'; DaysAgo = 46; Expected = $false }
            @{ Name = 'fails after a year'; DaysAgo = 365; Expected = $false }
            @{ Name = 'fails when the password was never set'; DaysAgo = $null; Expected = $false }
        ) {
            Use-Ad -Computer @(Get-ComputerFixture -PasswordDaysAgo $DaysAgo)

            Test-MtAnssiAdDcStalePassword | Should -Be $Expected
        }

        It 'fails when one of several controllers is stale' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'A'
                Get-ComputerFixture -Name 'B' -PasswordDaysAgo 90
                Get-ComputerFixture -Name 'C'
            )

            Test-MtAnssiAdDcStalePassword | Should -Be $false
        }

        It 'evaluates read-only domain controllers' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'RO1' -PrimaryGroupId 521 -PasswordDaysAgo 90
            )

            Test-MtAnssiAdDcStalePassword | Should -Be $false
        }

        It 'ignores computers that are not domain controllers' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'DC1'
                Get-ComputerFixture -Name 'PC1' -PrimaryGroupId 515 -PasswordDaysAgo 400
            )

            Test-MtAnssiAdDcStalePassword | Should -BeTrue
        }

        It 'ignores disabled domain controller accounts' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'DC1'
                Get-ComputerFixture -Name 'OLD' -PasswordDaysAgo 400 -Enabled $false
            )

            Test-MtAnssiAdDcStalePassword | Should -BeTrue
        }
    }

    Context 'result text' {
        It 'counts the controllers when the test passes' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'A'; Get-ComputerFixture -Name 'B')

            $null = Test-MtAnssiAdDcStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 enabled domain controllers changed their password within ' +
                'the last 45 days\.$'
            }
        }

        It 'lists stale controllers with type, date and age, oldest first' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'FINE'
                Get-ComputerFixture -Name 'NEWER' -PrimaryGroupId 521 -PasswordDaysAgo 60
                Get-ComputerFixture -Name 'OLDEST' -PasswordDaysAgo 120
            )

            $null = Test-MtAnssiAdDcStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match '2 of 3 enabled domain controller computer accounts' -and
                $Result -match '\| contoso\.com \|' -and
                $Result -match '(?s)OLDEST \| Writable \| \d{4}-\d{2}-\d{2} \| 12[01] \|.*' +
                'NEWER \| ReadOnly \| \d{4}-\d{2}-\d{2} \| (59|60) \|' -and
                $Result -notmatch 'FINE'
            }
        }

        It 'shows Never and n/a when the password was never set' {
            Use-Ad -Computer @(Get-ComputerFixture -PasswordDaysAgo $null)

            $null = Test-MtAnssiAdDcStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'DC1 \| Writable \| Never \| n/a \|'
            }
        }

        It 'escapes markdown in the controller name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -PasswordDaysAgo 90)

            $null = Test-MtAnssiAdDcStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers and DomainControllers categories' {
            Use-Ad -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdDcStalePassword

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Computers' -and
                $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no domain controller computer account is found' {
            Use-Ad -Computer @(Get-ComputerFixture -PrimaryGroupId 515)

            Test-MtAnssiAdDcStalePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match 'enabled domain controller'
            }
        }

        It 'is skipped when every domain controller account is disabled' {
            Use-Ad -Computer @(Get-ComputerFixture -Enabled $false)

            Test-MtAnssiAdDcStalePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'is skipped when there is no computer data' {
            Use-Ad -Computer $null

            Test-MtAnssiAdDcStalePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDcStalePassword } | Should -Throw 'LDAP bind failed'

        }
    }
}
