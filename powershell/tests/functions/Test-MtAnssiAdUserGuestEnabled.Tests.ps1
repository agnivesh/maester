BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-042.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdUserGuestEnabled' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdUserGuestEnabled {
        InModuleScope Maester { Test-MtAnssiAdUserGuestEnabled }
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
            [string] $Rid = '1100',
            [bool] $Enabled = $true
        )
        # Outside Windows the collector returns an object with a Value property, not a
        # SecurityIdentifier, so the fixtures use that shape on every platform.
        $sid = [PSCustomObject]@{ Value = "S-1-5-21-1-2-3-$Rid" }
        [PSCustomObject]@{
            SamAccountName = $Name
            Sid            = $sid
            Enabled        = $Enabled
            LastLogonDate  = $null
        }
    }
}

Describe 'Test-MtAnssiAdUserGuestEnabled' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'state of the Guest account' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails when the Guest account is enabled'
                GuestName = 'Guest'; GuestEnabled = $true; Expected = $false }
            @{ Name = 'fails when a renamed Guest account is enabled'
                GuestName = 'visitor'; GuestEnabled = $true; Expected = $false }
            @{ Name = 'passes when the Guest account is disabled'
                GuestName = 'Guest'; GuestEnabled = $false; Expected = $true }
        ) {
            $state = [PSCustomObject]@{
                Users = @(
                    Get-UserFixture -Name 'alice'
                    Get-UserFixture -Name $GuestName -Rid '501' -Enabled $GuestEnabled
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserGuestEnabled | Should -Be $Expected
        }

        It 'does not mistake an account whose RID only ends in 501 for the Guest account' {
            $state = [PSCustomObject]@{
                Users = @(
                    Get-UserFixture -Name 'Guest' -Rid '501' -Enabled $false
                    Get-UserFixture -Name 'other' -Rid '1501' -Enabled $true
                    Get-UserFixture -Name 'another' -Rid '5011' -Enabled $true
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserGuestEnabled | Should -BeTrue
        }

        # $IsWindows does not exist in Windows PowerShell 5.1, which only runs on Windows.
        It 'finds the Guest account when the SID is a SecurityIdentifier' `
            -Skip:($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
            $guest = Get-UserFixture -Name 'Guest' -Rid '501' -Enabled $true
            $guest.Sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-501')
            $state = [PSCustomObject]@{ Users = @($guest) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserGuestEnabled | Should -Be $false
        }

        It 'reads only the Users category of the AD state' {
            $state = [PSCustomObject]@{ Users = @(Get-UserFixture -Name 'Guest' -Rid '501') }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserGuestEnabled

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Users' }
        }
    }

    Context 'result text' {
        It 'shows the account and its SID when the Guest account is enabled' {
            $state = [PSCustomObject]@{
                Users = @(Get-UserFixture -Name 'visitor' -Rid '501' -Enabled $true)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserGuestEnabled

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'The Guest account is enabled' -and
                $Result -match 'visitor \| Never \| S-1-5-21-1-2-3-501'
            }
        }

        It 'says the Guest account is disabled when it is' {
            $state = [PSCustomObject]@{
                Users = @(Get-UserFixture -Name 'Guest' -Rid '501' -Enabled $false)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserGuestEnabled

            Should -Invoke @detail -ParameterFilter { $Result -eq 'The Guest account is disabled.' }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the Guest account is not in the collected data' {
            $state = [PSCustomObject]@{ Users = @(Get-UserFixture -Name 'alice') }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserGuestEnabled | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'Guest account'
            }
        }

        It 'is skipped when there is no user data' {
            $state = [PSCustomObject]@{ Users = $null }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserGuestEnabled | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdUserGuestEnabled } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'account names come from the directory' {
        It 'escapes markdown in the account name' {
            $evil = '[click](https://evil.example)|x'
            $state = [PSCustomObject]@{
                Users = @(Get-UserFixture -Name $evil -Rid '501' -Enabled $true)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserGuestEnabled

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }
}
