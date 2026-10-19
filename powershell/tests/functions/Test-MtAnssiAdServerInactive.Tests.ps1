BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-059.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdServerInactive' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdServerInactive {
        InModuleScope Maester { Test-MtAnssiAdServerInactive }
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
            [AllowNull()] [Nullable[int]] $LogonDaysAgo = 1,
            [AllowNull()] [Nullable[bool]] $Enabled = $true,
            [int] $PasswordDaysAgo = 500
        )
        $now = (Get-Date).ToUniversalTime()
        $lastLogon = $null
        if ($null -ne $LogonDaysAgo) { $lastLogon = $now.AddDays(-$LogonDaysAgo) }
        [PSCustomObject]@{
            DistinguishedName    = "CN=$Name,CN=Computers,DC=contoso,DC=com"
            Name                 = $Name
            OperatingSystem      = $OperatingSystem
            ServicePrincipalName = $ServicePrincipalName
            PrimaryGroupId       = $PrimaryGroupId
            Enabled              = $Enabled
            LastLogonDate        = $lastLogon
            PasswordLastSet      = $now.AddDays(-$PasswordDaysAgo)
        }
    }

    function Use-Ad {
        param([object[]] $Computer)
        $state = [PSCustomObject]@{ Computers = $Computer; DomainControllers = @() }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdServerInactive' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'last authentication' {
        It '<Name>' -ForEach @(
            @{ Name = 'passes when it authenticated today'; DaysAgo = 0; Expected = $true }
            @{ Name = 'passes after 30 days'; DaysAgo = 30; Expected = $true }
            @{ Name = 'passes after 60 days'; DaysAgo = 60; Expected = $true }
            @{ Name = 'passes just under 90 days'; DaysAgo = 89; Expected = $true }
            @{ Name = 'fails just over 90 days'; DaysAgo = 91; Expected = $false }
            @{ Name = 'fails after a year'; DaysAgo = 365; Expected = $false }
            @{ Name = 'passes when the server has no recorded logon'; DaysAgo = $null
                Expected = $true }
        ) {
            Use-Ad -Computer @(Get-ComputerFixture -LogonDaysAgo $DaysAgo)

            Test-MtAnssiAdServerInactive | Should -Be $Expected
        }

        It 'does not use the age of the password' {
            Use-Ad -Computer @(Get-ComputerFixture -LogonDaysAgo 1 -PasswordDaysAgo 500)

            Test-MtAnssiAdServerInactive | Should -BeTrue
        }

        It 'fails when one of several servers is inactive' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'A'
                Get-ComputerFixture -Name 'B' -LogonDaysAgo 150
                Get-ComputerFixture -Name 'C'
            )

            Test-MtAnssiAdServerInactive | Should -Be $false
        }

        It 'ignores workstations' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'PC1' -OperatingSystem 'Windows 11 Pro' `
                    -LogonDaysAgo 500
            )

            Test-MtAnssiAdServerInactive | Should -BeTrue
        }

        It 'ignores domain controllers' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516 -LogonDaysAgo 500
            )

            Test-MtAnssiAdServerInactive | Should -BeTrue
        }

        It 'ignores cluster accounts' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'CLUSTER1' -OperatingSystem '' -LogonDaysAgo 500 `
                    -ServicePrincipalName 'MSClusterVirtualServer/CLUSTER1'
            )

            Test-MtAnssiAdServerInactive | Should -BeTrue
        }

        It 'ignores disabled servers' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'OLD' -LogonDaysAgo 500 -Enabled $false
            )

            Test-MtAnssiAdServerInactive | Should -BeTrue
        }
    }

    Context 'result text' {
        It 'counts the servers when the test passes' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'A'; Get-ComputerFixture -Name 'B')

            $null = Test-MtAnssiAdServerInactive

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 enabled servers authenticated within the last 90 days\.$'
            }
        }

        It 'lists inactive servers with system, date and age, oldest first' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'FINE'
                Get-ComputerFixture -Name 'NEWER' -LogonDaysAgo 100 `
                    -OperatingSystem 'Windows Server 2016 Standard'
                Get-ComputerFixture -Name 'OLDEST' -LogonDaysAgo 200 `
                    -OperatingSystem 'Windows Server 2022 Standard'
            )

            $null = Test-MtAnssiAdServerInactive

            Should -Invoke @detail -ParameterFilter {
                $Result -match '2 of 3 enabled servers' -and
                $Result -match '\| contoso\.com \|' -and
                $Result -match '(?s)OLDEST \| Windows Server 2022 Standard \| ' +
                '\d{4}-\d{2}-\d{2} \| 20[01] \|.*' +
                'NEWER \| Windows Server 2016 Standard \| \d{4}-\d{2}-\d{2} \| (99|100) \|' -and
                $Result -notmatch 'FINE'
            }
        }

        It 'escapes markdown in the server name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -LogonDaysAgo 150)

            $null = Test-MtAnssiAdServerInactive

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers and DomainControllers categories' {
            Use-Ad -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdServerInactive

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

            Test-MtAnssiAdServerInactive | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'enabled server'
            }
        }

        It 'is skipped when every server account is disabled' {
            Use-Ad -Computer @(Get-ComputerFixture -Enabled $false)

            Test-MtAnssiAdServerInactive | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'is skipped when there is no computer data' {
            Use-Ad -Computer $null

            Test-MtAnssiAdServerInactive | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdServerInactive } | Should -Throw 'LDAP bind failed'

        }
    }
}
