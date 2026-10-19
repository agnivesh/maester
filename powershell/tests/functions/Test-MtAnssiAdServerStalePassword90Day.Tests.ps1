BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-046.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdServerStalePassword90Day' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdServerStalePassword90Day {
        InModuleScope Maester { Test-MtAnssiAdServerStalePassword90Day }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-ComputerFixture {
        param(
            [string] $Name = 'SRV1',
            [string] $OperatingSystem = 'Windows Server 2022 Standard',
            [string[]] $ServicePrincipalName = @(),
            [int] $PrimaryGroupId = 515,
            [AllowNull()] [Nullable[int]] $PasswordDaysAgo = 10,
            [AllowNull()] [Nullable[bool]] $Enabled = $true
        )
        $passwordLastSet = $null
        if ($null -ne $PasswordDaysAgo) {
            $passwordLastSet = (Get-Date).ToUniversalTime().AddDays(-$PasswordDaysAgo)
        }
        [PSCustomObject]@{
            DistinguishedName    = "CN=$Name,CN=Computers,DC=contoso,DC=com"
            Name                 = $Name
            OperatingSystem      = $OperatingSystem
            ServicePrincipalName = $ServicePrincipalName
            PrimaryGroupId       = $PrimaryGroupId
            Enabled              = $Enabled
            PasswordLastSet      = $passwordLastSet
        }
    }

    function Use-Ad {
        param([object[]] $Computer)
        $state = [PSCustomObject]@{ Computers = $Computer; DomainControllers = @() }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdServerStalePassword90Day' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'age of the password' {
        It '<Name>' -ForEach @(
            @{ Name = 'passes with the default change of 30 days'; DaysAgo = 30; Expected = $true }
            @{ Name = 'passes after 60 days, which fails the 45 day test'; DaysAgo = 60
                Expected = $true }
            @{ Name = 'passes just under 90 days'; DaysAgo = 89; Expected = $true }
            @{ Name = 'fails just over 90 days'; DaysAgo = 91; Expected = $false }
            @{ Name = 'fails after a year'; DaysAgo = 365; Expected = $false }
            @{ Name = 'fails when the password was never set'; DaysAgo = $null; Expected = $false }
        ) {
            Use-Ad -Computer @(Get-ComputerFixture -PasswordDaysAgo $DaysAgo)

            Test-MtAnssiAdServerStalePassword90Day | Should -Be $Expected
        }

        It 'fails when one of several servers is stale' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'A'
                Get-ComputerFixture -Name 'B' -PasswordDaysAgo 150
                Get-ComputerFixture -Name 'C'
            )

            Test-MtAnssiAdServerStalePassword90Day | Should -Be $false
        }

        It 'ignores workstations' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'PC1' -OperatingSystem 'Windows 11 Pro' `
                    -PasswordDaysAgo 500
            )

            Test-MtAnssiAdServerStalePassword90Day | Should -BeTrue
        }

        It 'ignores domain controllers' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516 -PasswordDaysAgo 500
            )

            Test-MtAnssiAdServerStalePassword90Day | Should -BeTrue
        }

        It 'ignores cluster accounts' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'CLUSTER1' -OperatingSystem '' -PasswordDaysAgo 500 `
                    -ServicePrincipalName 'MSClusterVirtualServer/CLUSTER1'
            )

            Test-MtAnssiAdServerStalePassword90Day | Should -BeTrue
        }

        It 'ignores disabled servers' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'OLD' -PasswordDaysAgo 500 -Enabled $false
            )

            Test-MtAnssiAdServerStalePassword90Day | Should -BeTrue
        }
    }

    Context 'result text' {
        It 'counts the servers when the test passes' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'A'; Get-ComputerFixture -Name 'B')

            $null = Test-MtAnssiAdServerStalePassword90Day

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 enabled servers changed their password within the last ' +
                '90 days\.$'
            }
        }

        It 'lists stale servers with system, date and age, oldest first' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'FINE'
                Get-ComputerFixture -Name 'NEWER' -PasswordDaysAgo 100 `
                    -OperatingSystem 'Windows Server 2016 Standard'
                Get-ComputerFixture -Name 'OLDEST' -PasswordDaysAgo 200 `
                    -OperatingSystem 'Windows Server 2022 Standard'
            )

            $null = Test-MtAnssiAdServerStalePassword90Day

            Should -Invoke @detail -ParameterFilter {
                $Result -match '2 of 3 enabled servers' -and
                $Result -match '\| contoso\.com \|' -and
                $Result -match '(?s)OLDEST \| Windows Server 2022 Standard \| ' +
                '\d{4}-\d{2}-\d{2} \| 20[01] \|.*' +
                'NEWER \| Windows Server 2016 Standard \| \d{4}-\d{2}-\d{2} \| (99|100) \|' -and
                $Result -notmatch 'FINE'
            }
        }

        It 'shows Never and n/a when the password was never set' {
            Use-Ad -Computer @(Get-ComputerFixture -PasswordDaysAgo $null)

            $null = Test-MtAnssiAdServerStalePassword90Day

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'SRV1 \| .* \| Never \| n/a \|'
            }
        }

        It 'escapes markdown in the server name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -PasswordDaysAgo 150)

            $null = Test-MtAnssiAdServerStalePassword90Day

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers and DomainControllers categories' {
            Use-Ad -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdServerStalePassword90Day

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Computers' -and
                $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when there is no server computer account' {
            Use-Ad -Computer @(Get-ComputerFixture -OperatingSystem 'Windows 11 Pro')

            Test-MtAnssiAdServerStalePassword90Day | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'enabled server'
            }
        }

        It 'is skipped when every server account is disabled' {
            Use-Ad -Computer @(Get-ComputerFixture -Enabled $false)

            Test-MtAnssiAdServerStalePassword90Day | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'is skipped when there is no computer data' {
            Use-Ad -Computer $null

            Test-MtAnssiAdServerStalePassword90Day | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdServerStalePassword90Day } | Should -Throw 'LDAP bind failed'

        }
    }
}
