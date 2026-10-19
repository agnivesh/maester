BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-047.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdClusterStalePassword' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdClusterStalePassword {
        InModuleScope Maester { Test-MtAnssiAdClusterStalePassword }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-ComputerFixture {
        param(
            [string] $Name = 'CLUSTER1',
            [string] $OperatingSystem = '',
            [string[]] $ServicePrincipalName = @('MSClusterVirtualServer/CLUSTER1'),
            [int] $PrimaryGroupId = 515,
            [AllowNull()] [Nullable[int]] $PasswordDaysAgo = 100,
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

Describe 'Test-MtAnssiAdClusterStalePassword' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'age of the password' {
        It '<Name>' -ForEach @(
            @{ Name = 'passes for a password set today'; DaysAgo = 0; Expected = $true }
            @{ Name = 'passes after a year'; DaysAgo = 365; Expected = $true }
            @{ Name = 'passes just under 3 years'; DaysAgo = 1090; Expected = $true }
            @{ Name = 'fails just over 3 years'; DaysAgo = 1100; Expected = $false }
            @{ Name = 'fails after 5 years'; DaysAgo = 1825; Expected = $false }
            @{ Name = 'fails when the password was never set'; DaysAgo = $null; Expected = $false }
        ) {
            Use-Ad -Computer @(Get-ComputerFixture -PasswordDaysAgo $DaysAgo)

            Test-MtAnssiAdClusterStalePassword | Should -Be $Expected
        }

        It 'fails when one of several cluster accounts is stale' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'A'
                Get-ComputerFixture -Name 'B' -PasswordDaysAgo 1500
                Get-ComputerFixture -Name 'C'
            )

            Test-MtAnssiAdClusterStalePassword | Should -Be $false
        }

        It 'checks cluster accounts that carry an operating system as well' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'NODEACCOUNT' -PasswordDaysAgo 1500 `
                    -OperatingSystem 'Windows Server 2022 Standard'
            )

            Test-MtAnssiAdClusterStalePassword | Should -Be $false
        }

        It 'ignores ordinary servers, whatever the age of their password' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'SRV1' -ServicePrincipalName @() -PasswordDaysAgo 2000 `
                    -OperatingSystem 'Windows Server 2022 Standard'
            )

            Test-MtAnssiAdClusterStalePassword | Should -BeTrue
        }

        It 'ignores disabled cluster accounts, such as a prestaged cluster name account' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'PRESTAGED' -PasswordDaysAgo 2000 -Enabled $false
            )

            Test-MtAnssiAdClusterStalePassword | Should -BeTrue
        }
    }

    Context 'result text' {
        It 'counts the accounts when the test passes' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'A'; Get-ComputerFixture -Name 'B')

            $null = Test-MtAnssiAdClusterStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 enabled cluster accounts changed their password within ' +
                'the last 3 years\.$'
            }
        }

        It 'lists stale accounts with date and age, oldest first' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'FINE'
                Get-ComputerFixture -Name 'ANEWER' -PasswordDaysAgo 1200
                Get-ComputerFixture -Name 'ZOLDEST' -PasswordDaysAgo 2000
            )

            $null = Test-MtAnssiAdClusterStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match '2 of 3 enabled cluster accounts' -and
                $Result -match '\| contoso\.com \|' -and
                $Result -match '(?s)ZOLDEST \| \d{4}-\d{2}-\d{2} \| 200[01] \|.*' +
                'ANEWER \| \d{4}-\d{2}-\d{2} \| (1199|1200) \|' -and
                $Result -notmatch 'FINE'
            }
        }

        It 'shows Never and n/a when the password was never set' {
            Use-Ad -Computer @(Get-ComputerFixture -PasswordDaysAgo $null)

            $null = Test-MtAnssiAdClusterStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'CLUSTER1 \| Never \| n/a \|'
            }
        }

        It 'escapes markdown in the account name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -PasswordDaysAgo 1500)

            $null = Test-MtAnssiAdClusterStalePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers and DomainControllers categories' {
            Use-Ad -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdClusterStalePassword

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Computers' -and
                $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when there is no cluster account' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'SRV1' -ServicePrincipalName @() `
                    -OperatingSystem 'Windows Server 2022 Standard'
            )

            Test-MtAnssiAdClusterStalePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'enabled cluster'
            }
        }

        It 'is skipped when every cluster account is disabled' {
            Use-Ad -Computer @(Get-ComputerFixture -Enabled $false)

            Test-MtAnssiAdClusterStalePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'is skipped when there is no computer data' {
            Use-Ad -Computer $null

            Test-MtAnssiAdClusterStalePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdClusterStalePassword } | Should -Throw 'LDAP bind failed'

        }
    }
}
