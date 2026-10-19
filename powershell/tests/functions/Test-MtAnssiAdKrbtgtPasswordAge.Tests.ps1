BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-045.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdKrbtgtPasswordAge' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdKrbtgtPasswordAge {
        InModuleScope Maester { Test-MtAnssiAdKrbtgtPasswordAge }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-AccountFixture {
        param(
            [string] $Name = 'krbtgt',
            [string] $Rid = '502',
            [AllowNull()] [Nullable[int]] $PasswordDaysAgo = 30
        )
        $passwordLastSet = $null
        if ($null -ne $PasswordDaysAgo) {
            $passwordLastSet = (Get-Date).ToUniversalTime().AddDays(-$PasswordDaysAgo)
        }
        # Outside Windows the collector returns an object with a Value property, not a
        # SecurityIdentifier, so the fixtures use that shape on every platform.
        [PSCustomObject]@{
            SamAccountName  = $Name
            Sid             = [PSCustomObject]@{ Value = "S-1-5-21-1-2-3-$Rid" }
            PasswordLastSet = $passwordLastSet
        }
    }
}

Describe 'Test-MtAnssiAdKrbtgtPasswordAge' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'age of the krbtgt password' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails when the password is more than a year old'
                DaysAgo = 400; Expected = $false }
            @{ Name = 'fails when the password is just over a year old'
                DaysAgo = 370; Expected = $false }
            @{ Name = 'passes when the password changed within the year'
                DaysAgo = 360; Expected = $true }
            @{ Name = 'passes when the password changed today'
                DaysAgo = 0; Expected = $true }
            @{ Name = 'fails when the password was never set'
                DaysAgo = $null; Expected = $false }
        ) {
            $account = Get-AccountFixture -PasswordDaysAgo $DaysAgo
            $others = Get-AccountFixture -Name 'alice' -Rid '1100'
            $state = [PSCustomObject]@{ Users = @($others, $account) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdKrbtgtPasswordAge | Should -Be $Expected
        }

        It 'finds a renamed krbtgt account by its relative identifier' {
            $state = [PSCustomObject]@{
                Users = @(Get-AccountFixture -Name 'renamed' -PasswordDaysAgo 500)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdKrbtgtPasswordAge | Should -Be $false
        }

        It 'does not mistake an account whose RID only ends in 502 for krbtgt' {
            $state = [PSCustomObject]@{
                Users = @(
                    Get-AccountFixture -Name 'krbtgt' -PasswordDaysAgo 10
                    Get-AccountFixture -Name 'other' -Rid '1502' -PasswordDaysAgo 900
                    Get-AccountFixture -Name 'krbtgt_1234' -Rid '5021' -PasswordDaysAgo 900
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdKrbtgtPasswordAge | Should -BeTrue
        }

        It 'reads only the Users category of the AD state' {
            $state = [PSCustomObject]@{ Users = @(Get-AccountFixture) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdKrbtgtPasswordAge

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Users' }
        }
    }

    Context 'result text' {
        It 'gives the date of the last change when the test passes' {
            $state = [PSCustomObject]@{ Users = @(Get-AccountFixture -PasswordDaysAgo 20) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdKrbtgtPasswordAge

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'The krbtgt password was last changed on \d{4}-\d{2}-\d{2}\.$'
            }
        }

        It 'shows the account, the date and the age in days when the test fails' {
            $state = [PSCustomObject]@{ Users = @(Get-AccountFixture -PasswordDaysAgo 400) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdKrbtgtPasswordAge

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'golden tickets' -and
                $Result -match 'krbtgt \| \d{4}-\d{2}-\d{2} \| (399|400) \|'
            }
        }

        It 'shows n/a as the age when the password was never set' {
            $state = [PSCustomObject]@{ Users = @(Get-AccountFixture -PasswordDaysAgo $null) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdKrbtgtPasswordAge

            Should -Invoke @detail -ParameterFilter { $Result -match 'krbtgt \| Never \| n/a \|' }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the krbtgt account is not in the collected data' {
            $state = [PSCustomObject]@{ Users = @(Get-AccountFixture -Name 'alice' -Rid '1100') }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdKrbtgtPasswordAge | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'krbtgt'
            }
        }

        It 'is skipped when there is no user data' {
            $state = [PSCustomObject]@{ Users = $null }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdKrbtgtPasswordAge | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdKrbtgtPasswordAge } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'account names come from the directory' {
        It 'escapes markdown in the account name' {
            $evil = '[click](https://evil.example)|x'
            $account = Get-AccountFixture -Name $evil -PasswordDaysAgo 500
            $state = [PSCustomObject]@{ Users = @($account) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdKrbtgtPasswordAge

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }
}
