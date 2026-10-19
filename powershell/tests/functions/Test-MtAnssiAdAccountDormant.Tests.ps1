BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-037.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdAccountDormant' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdAccountDormant {
        InModuleScope Maester { Test-MtAnssiAdAccountDormant }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-DaysAgo {
        param([AllowNull()] [Nullable[int]] $Days)
        if ($null -eq $Days) { return $null }
        (Get-Date).ToUniversalTime().AddDays(-$Days)
    }

    function Get-AccountFixture {
        param(
            [string] $Name = 'account',
            [bool] $Enabled = $true,
            [AllowNull()] [Nullable[int]] $PasswordDaysAgo = 30,
            [AllowNull()] [Nullable[int]] $LogonDaysAgo = 1,
            [AllowNull()] [Nullable[int]] $CreatedDaysAgo = 3000
        )
        [PSCustomObject]@{
            SamAccountName  = $Name
            Enabled         = $Enabled
            PasswordLastSet = Get-DaysAgo $PasswordDaysAgo
            LastLogonDate   = Get-DaysAgo $LogonDaysAgo
            Created         = Get-DaysAgo $CreatedDaysAgo
        }
    }

    # Passwords older than three years, no logon for over a year: dormant.
    function Get-DormantFixture {
        param([string] $Name = 'dormant')
        Get-AccountFixture -Name $Name -PasswordDaysAgo 1200 -LogonDaysAgo 400
    }

    function Get-AccountList {
        param([string] $Prefix, [int] $Dormant = 0, [int] $Active = 0)
        for ($i = 1; $i -le $Dormant; $i++) { Get-DormantFixture -Name "$Prefix-dormant$i" }
        for ($i = 1; $i -le $Active; $i++) { Get-AccountFixture -Name "$Prefix-active$i" }
    }
}

Describe 'Test-MtAnssiAdAccountDormant' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    # A single enabled account is 100% of the accounts: dormant fails, otherwise passes.
    Context 'what makes an account dormant' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails for an old password and no logon for over a year'
                Password = 1200; Logon = 400; Created = 3000; Expected = $false }
            @{ Name = 'passes when the account logged on within the year'
                Password = 1200; Logon = 360; Created = 3000; Expected = $true }
            @{ Name = 'fails when the last logon is just over a year ago'
                Password = 1200; Logon = 370; Created = 3000; Expected = $false }
            @{ Name = 'passes when the password changed within three years'
                Password = 1000; Logon = 400; Created = 3000; Expected = $true }
            @{ Name = 'fails when the account never logged on and was created over a year ago'
                Password = 1200; Logon = $null; Created = 400; Expected = $false }
            @{ Name = 'passes when the account never logged on but is recent'
                Password = 1200; Logon = $null; Created = 100; Expected = $true }
            @{ Name = 'fails when the password was never set'
                Password = $null; Logon = 400; Created = 3000; Expected = $false }
            @{ Name = 'passes when the password changed recently'
                Password = 30; Logon = 400; Created = 3000; Expected = $true }
        ) {
            $account = Get-AccountFixture -PasswordDaysAgo $Password -LogonDaysAgo $Logon `
                -CreatedDaysAgo $Created
            $state = [PSCustomObject]@{ Users = @($account); Computers = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdAccountDormant | Should -Be $Expected
        }

        It 'ignores disabled dormant accounts' {
            $disabled = Get-AccountFixture -Enabled $false -PasswordDaysAgo 1200 -LogonDaysAgo 400
            $state = [PSCustomObject]@{ Users = @($disabled); Computers = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdAccountDormant | Should -BeTrue

            Should -Invoke @detail -ParameterFilter { $Result -match 'No enabled account' }
        }

        It 'ignores disabled dormant computers' {
            $disabled = Get-AccountFixture -Name 'pc$' -Enabled $false -PasswordDaysAgo 1200 `
                -LogonDaysAgo 400
            $state = [PSCustomObject]@{ Users = @(); Computers = @($disabled) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdAccountDormant | Should -BeTrue

            Should -Invoke @detail -ParameterFilter { $Result -match 'No enabled account' }
        }

        It 'reads the Users and Computers categories of the AD state' {
            $state = [PSCustomObject]@{ Users = @(); Computers = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdAccountDormant

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Users' -and
                $Categories -contains 'Computers'
            }
        }
    }

    Context 'threshold of 25% of the enabled accounts, users and computers together' {
        It '<Name>' -ForEach @(
            @{ Name = 'passes at exactly 25%'
                UserDormant = 13; ComputerDormant = 12; Expected = $true }
            @{ Name = 'fails just above 25%'
                UserDormant = 13; ComputerDormant = 13; Expected = $false }
            @{ Name = 'passes with no dormant account'
                UserDormant = 0; ComputerDormant = 0; Expected = $true }
            @{ Name = 'counts only dormant users against the whole population'
                UserDormant = 26; ComputerDormant = 0; Expected = $false }
            @{ Name = 'counts only dormant computers against the whole population'
                UserDormant = 0; ComputerDormant = 25; Expected = $true }
        ) {
            $users = @(Get-AccountList -Prefix 'user' -Dormant $UserDormant `
                    -Active (50 - $UserDormant))
            $computers = @(Get-AccountList -Prefix 'pc' -Dormant $ComputerDormant `
                    -Active (50 - $ComputerDormant))
            $state = [PSCustomObject]@{ Users = $users; Computers = $computers }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdAccountDormant | Should -Be $Expected
        }
    }

    Context 'result text' {
        It 'gives the count and the rounded percentage when the test passes' {
            $users = @(Get-AccountList -Prefix 'user' -Dormant 1 -Active 11)
            $state = [PSCustomObject]@{ Users = $users; Computers = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdAccountDormant

            Should -Invoke @detail -ParameterFilter {
                $Result -match '1 of 12 enabled accounts \(8\.3%\) are dormant' -and
                $Result -match 'The limit is 25%' -and $Result -notmatch '\| Type \|'
            }
        }

        It 'lists the dormant accounts with their type, oldest password first' {
            $state = [PSCustomObject]@{
                Users     = @(
                    Get-AccountFixture -Name 'NEWER' -PasswordDaysAgo 1200 -LogonDaysAgo 400
                    Get-AccountFixture -Name 'OLDEST' -PasswordDaysAgo 5000 -LogonDaysAgo 900
                )
                Computers = @(
                    Get-AccountFixture -Name 'MIDDLE$' -PasswordDaysAgo 2000 -LogonDaysAgo 500
                    Get-AccountFixture -Name 'active$'
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdAccountDormant

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'User \| OLDEST \| \d{4}-\d{2}-\d{2} \|' -and
                $Result -match 'Computer \| MIDDLE\$ \|' -and
                $Result.IndexOf('OLDEST') -lt $Result.IndexOf('MIDDLE') -and
                $Result.IndexOf('MIDDLE') -lt $Result.IndexOf('NEWER') -and
                $Result -notmatch 'active' -and $Result -match 'more than the 25% limit'
            }
        }

        It 'shows Never for an account that never logged on' {
            $account = Get-AccountFixture -Name 'ghost' -PasswordDaysAgo 1200 -LogonDaysAgo $null `
                -CreatedDaysAgo 400
            $state = [PSCustomObject]@{ Users = @($account); Computers = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdAccountDormant

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'ghost \| \d{4}-\d{2}-\d{2} \| Never \| \d{4}-\d{2}-\d{2} \|'
            }
        }

        It 'caps the table at 100 accounts' {
            $users = @(Get-AccountList -Prefix 'user' -Dormant 150 -Active 50)
            $state = [PSCustomObject]@{ Users = $users; Computers = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdAccountDormant

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'Showing the first 100 of 150'
            }
        }
    }

    Context 'no enabled account' {
    }

    Context 'test cannot run' {
        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdAccountDormant } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'account names come from the directory' {
        It 'escapes markdown in the account name' {
            $evil = '[click](https://evil.example)|x'
            $state = [PSCustomObject]@{
                Users     = @(Get-DormantFixture -Name $evil)
                Computers = @()
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdAccountDormant

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    It 'is skipped when the <Collection> collection was not returned' -ForEach @(
        @{ Collection = 'Users' }
        @{ Collection = 'Computers' }
    ) {
        $props = [ordered]@{ Users = @(); Computers = @() }
        $props[$Collection] = $null
        $state = [PSCustomObject]$props
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

        Test-MtAnssiAdAccountDormant | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
