BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-041.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdUserNeverExpiringPassword' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdUserNeverExpiringPassword {
        InModuleScope Maester { Test-MtAnssiAdUserNeverExpiringPassword }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-UserFixture {
        param(
            [string] $Name = 'user',
            [bool] $Enabled = $true,
            [bool] $NeverExpires = $false,
            [int] $PasswordDaysAgo = 30
        )
        [PSCustomObject]@{
            SamAccountName       = $Name
            Enabled              = $Enabled
            PasswordNeverExpires = $NeverExpires
            PasswordLastSet      = (Get-Date).ToUniversalTime().AddDays(-$PasswordDaysAgo)
            LastLogonDate        = $null
        }
    }

    # A population with the given number of normal and never-expiring accounts.
    function Get-Population {
        param(
            [int] $Normal = 0,
            [int] $NeverExpiring = 0,
            [bool] $Enabled = $true
        )
        for ($i = 1; $i -le $Normal; $i++) {
            Get-UserFixture -Name "normal$i" -Enabled $Enabled
        }
        for ($i = 1; $i -le $NeverExpiring; $i++) {
            Get-UserFixture -Name "never$i" -Enabled $Enabled -NeverExpires $true
        }
    }
}

Describe 'Test-MtAnssiAdUserNeverExpiringPassword' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'threshold of 10% of the enabled accounts' {
        It '<Name>' -ForEach @(
            @{ Name = 'passes with no never-expiring password'
                Normal = 100; Never = 0; Expected = $true }
            @{ Name = 'passes at exactly 10%'
                Normal = 90; Never = 10; Expected = $true }
            @{ Name = 'fails just above 10%'
                Normal = 89; Never = 11; Expected = $false }
            @{ Name = 'fails when every account never expires'
                Normal = 0; Never = 1; Expected = $false }
            @{ Name = 'passes at exactly 10% on a small population'
                Normal = 9; Never = 1; Expected = $true }
            @{ Name = 'fails at 20% on a small population'
                Normal = 4; Never = 1; Expected = $false }
        ) {
            $users = @(Get-Population -Normal $Normal -NeverExpiring $Never)
            $state = [PSCustomObject]@{ Users = $users }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserNeverExpiringPassword | Should -Be $Expected
        }

        It 'ignores disabled accounts in the count' {
            $users = @(Get-Population -Normal 100 -NeverExpiring 5) +
                @(Get-Population -Normal 0 -NeverExpiring 50 -Enabled $false)
            $state = [PSCustomObject]@{ Users = $users }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserNeverExpiringPassword | Should -BeTrue
        }

        It 'ignores disabled accounts in the total' {
            $users = @(Get-Population -Normal 71 -NeverExpiring 9) +
                @(Get-Population -Normal 100 -NeverExpiring 0 -Enabled $false)
            $state = [PSCustomObject]@{ Users = $users }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserNeverExpiringPassword | Should -Be $false
        }

        It 'reads only the Users category of the AD state' {
            $state = [PSCustomObject]@{ Users = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserNeverExpiringPassword

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Users' }
        }
    }

    Context 'result text' {
        It 'gives the count and the rounded percentage when the test passes' {
            $state = [PSCustomObject]@{ Users = @(Get-Population -Normal 11 -NeverExpiring 1) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserNeverExpiringPassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match '1 of 12 enabled user accounts \(8\.3%\)' -and
                $Result -notmatch '\| Account \|'
            }
        }

        It 'lists the accounts with the oldest password first when the test fails' {
            $state = [PSCustomObject]@{
                Users = @(
                    Get-UserFixture -Name 'NEWER' -NeverExpires $true -PasswordDaysAgo 10
                    Get-UserFixture -Name 'OLDEST' -NeverExpires $true -PasswordDaysAgo 4000
                    Get-UserFixture -Name 'MIDDLE' -NeverExpires $true -PasswordDaysAgo 400
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserNeverExpiringPassword

            Should -Invoke @detail -ParameterFilter {
                $Result.IndexOf('OLDEST') -ge 0 -and
                $Result.IndexOf('OLDEST') -lt $Result.IndexOf('MIDDLE') -and
                $Result.IndexOf('MIDDLE') -lt $Result.IndexOf('NEWER') -and
                $Result -match 'more than the 10% limit'
            }
        }

        It 'caps the table at 100 accounts' {
            $state = [PSCustomObject]@{ Users = @(Get-Population -Normal 50 -NeverExpiring 150) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserNeverExpiringPassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'Showing the first 100 of 150' -and $Result -notmatch 'normal1 '
            }
        }

        It 'does not list accounts whose password can expire' {
            $state = [PSCustomObject]@{ Users = @(Get-Population -Normal 5 -NeverExpiring 5) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserNeverExpiringPassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'never1 ' -and $Result -notmatch 'normal'
            }
        }
    }

    Context 'no enabled user account' {
        It 'passes and says so for disabled accounts only' {
            $state = [PSCustomObject]@{
                Users = @(Get-Population -Normal 0 -NeverExpiring 3 -Enabled $false)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserNeverExpiringPassword | Should -BeTrue

            Should -Invoke @detail -ParameterFilter { $Result -match 'No enabled user account' }
        }

    }

    Context 'test cannot run' {
        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdUserNeverExpiringPassword } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'account names come from the directory' {
        It 'escapes markdown in the account name' {
            $evil = '[click](https://evil.example)|x'
            $state = [PSCustomObject]@{
                Users = @(Get-UserFixture -Name $evil -NeverExpires $true)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserNeverExpiringPassword

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    It 'is skipped when the <Collection> collection was not returned' -ForEach @(
        @{ Collection = 'Users' }
    ) {
        $props = [ordered]@{ Users = @() }
        $props[$Collection] = $null
        $state = [PSCustomObject]$props
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

        Test-MtAnssiAdUserNeverExpiringPassword | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
