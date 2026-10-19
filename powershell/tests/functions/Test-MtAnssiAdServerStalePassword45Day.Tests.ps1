BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-060.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdServerStalePassword45Day' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdServerStalePassword45Day {
        InModuleScope Maester { Test-MtAnssiAdServerStalePassword45Day }
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

Describe 'Test-MtAnssiAdServerStalePassword45Day' {
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

            Test-MtAnssiAdServerStalePassword45Day | Should -Be $Expected
        }

        It 'fails when one of several servers is stale' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'A'
                Get-ComputerFixture -Name 'B' -PasswordDaysAgo 90
                Get-ComputerFixture -Name 'C'
            )

            Test-MtAnssiAdServerStalePassword45Day | Should -Be $false
        }

        It 'ignores workstations' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'PC1' -OperatingSystem 'Windows 11 Pro' `
                    -PasswordDaysAgo 400
            )

            Test-MtAnssiAdServerStalePassword45Day | Should -BeTrue
        }

        It 'ignores domain controllers' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516 -PasswordDaysAgo 400
            )

            Test-MtAnssiAdServerStalePassword45Day | Should -BeTrue
        }

        It 'ignores cluster accounts' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'CLUSTER1' -OperatingSystem '' -PasswordDaysAgo 400 `
                    -ServicePrincipalName 'MSClusterVirtualServer/CLUSTER1'
            )

            Test-MtAnssiAdServerStalePassword45Day | Should -BeTrue
        }

        It 'ignores disabled servers' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'OLD' -PasswordDaysAgo 400 -Enabled $false
            )

            Test-MtAnssiAdServerStalePassword45Day | Should -BeTrue
        }
    }

    Context 'result text' {
        It 'counts the servers when the test passes' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'A'; Get-ComputerFixture -Name 'B')

            $null = Test-MtAnssiAdServerStalePassword45Day

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 enabled servers changed their password within the last ' +
                '45 days\.$'
            }
        }

        It 'lists stale servers with system, date and age, oldest first' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'FINE'
                Get-ComputerFixture -Name 'NEWER' -PasswordDaysAgo 60 `
                    -OperatingSystem 'Windows Server 2016 Standard'
                Get-ComputerFixture -Name 'OLDEST' -PasswordDaysAgo 120 `
                    -OperatingSystem 'Windows Server 2022 Standard'
            )

            $null = Test-MtAnssiAdServerStalePassword45Day

            Should -Invoke @detail -ParameterFilter {
                $Result -match '2 of 3 enabled servers' -and
                $Result -match '\| contoso\.com \|' -and
                $Result -match '(?s)OLDEST \| Windows Server 2022 Standard \| ' +
                '\d{4}-\d{2}-\d{2} \| 12[01] \|.*' +
                'NEWER \| Windows Server 2016 Standard \| \d{4}-\d{2}-\d{2} \| (59|60) \|' -and
                $Result -notmatch 'FINE'
            }
        }

        It 'shows Never and n/a when the password was never set' {
            Use-Ad -Computer @(Get-ComputerFixture -PasswordDaysAgo $null)

            $null = Test-MtAnssiAdServerStalePassword45Day

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'SRV1 \| .* \| Never \| n/a \|'
            }
        }

        It 'escapes markdown in the server name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -PasswordDaysAgo 90)

            $null = Test-MtAnssiAdServerStalePassword45Day

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers and DomainControllers categories' {
            Use-Ad -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdServerStalePassword45Day

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

            Test-MtAnssiAdServerStalePassword45Day | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'enabled server'
            }
        }

        It 'is skipped when every server account is disabled' {
            Use-Ad -Computer @(Get-ComputerFixture -Enabled $false)

            Test-MtAnssiAdServerStalePassword45Day | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'is skipped when there is no computer data' {
            Use-Ad -Computer $null

            Test-MtAnssiAdServerStalePassword45Day | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdServerStalePassword45Day } | Should -Throw 'LDAP bind failed'

        }
    }
}
