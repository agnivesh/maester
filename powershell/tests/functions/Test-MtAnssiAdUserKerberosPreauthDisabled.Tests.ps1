BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-044.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdUserKerberosPreauthDisabled' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdUserKerberosPreauthDisabled {
        InModuleScope Maester { Test-MtAnssiAdUserKerberosPreauthDisabled }
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
            [bool] $NoPreAuth = $false,
            [AllowNull()] [Nullable[int]] $PasswordDaysAgo = 30
        )
        $passwordLastSet = $null
        if ($null -ne $PasswordDaysAgo) {
            $passwordLastSet = (Get-Date).ToUniversalTime().AddDays(-$PasswordDaysAgo)
        }
        [PSCustomObject]@{
            SamAccountName        = $Name
            Enabled               = $Enabled
            DoesNotRequirePreAuth = $NoPreAuth
            PasswordLastSet       = $passwordLastSet
            LastLogonDate         = $null
        }
    }
}

Describe 'Test-MtAnssiAdUserKerberosPreauthDisabled' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict for a single account' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails for an enabled account without preauthentication'
                Enabled = $true; NoPreAuth = $true; Expected = $false }
            @{ Name = 'passes for an enabled account that requires preauthentication'
                Enabled = $true; NoPreAuth = $false; Expected = $true }
            @{ Name = 'passes for a disabled account without preauthentication'
                Enabled = $false; NoPreAuth = $true; Expected = $true }
            @{ Name = 'passes for a disabled account that requires preauthentication'
                Enabled = $false; NoPreAuth = $false; Expected = $true }
        ) {
            $user = Get-UserFixture -Enabled $Enabled -NoPreAuth $NoPreAuth
            $state = [PSCustomObject]@{ Users = @($user) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserKerberosPreauthDisabled | Should -Be $Expected
        }

        It 'reads only the Users category of the AD state' {
            $state = [PSCustomObject]@{ Users = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserKerberosPreauthDisabled

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Users' }
        }
    }

    Context 'several accounts' {
        BeforeEach {
            $state = [PSCustomObject]@{
                Users = @(
                    Get-UserFixture -Name 'roastable' -NoPreAuth $true -PasswordDaysAgo 400
                    Get-UserFixture -Name 'neverset' -NoPreAuth $true -PasswordDaysAgo $null
                    Get-UserFixture -Name 'fine'
                    Get-UserFixture -Name 'disabledflagged' -Enabled $false -NoPreAuth $true
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        }

        It 'fails when at least one enabled account has preauthentication disabled' {
            Test-MtAnssiAdUserKerberosPreauthDisabled | Should -Be $false
        }

        It 'lists only the enabled accounts without preauthentication' {
            $null = Test-MtAnssiAdUserKerberosPreauthDisabled

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'Found 2 enabled account' -and
                $Result -match 'roastable \| \d{4}-\d{2}-\d{2} \|' -and
                $Result -match 'neverset \| Never \|' -and
                $Result -notmatch 'fine' -and
                $Result -notmatch 'disabledflagged'
            }
        }
    }

    Context 'no account without preauthentication' {
        It 'passes and says so' {
            $state = [PSCustomObject]@{ Users = @(Get-UserFixture -Name 'fine') }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserKerberosPreauthDisabled | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Result -eq 'No enabled account has Kerberos preauthentication disabled.'
            }
        }

    }

    Context 'test cannot run' {
        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdUserKerberosPreauthDisabled } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'account names come from the directory' {
        It 'escapes markdown in the account name' {
            $evil = '[click](https://evil.example)|x'
            $state = [PSCustomObject]@{ Users = @(Get-UserFixture -Name $evil -NoPreAuth $true) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserKerberosPreauthDisabled

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

        Test-MtAnssiAdUserKerberosPreauthDisabled | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
