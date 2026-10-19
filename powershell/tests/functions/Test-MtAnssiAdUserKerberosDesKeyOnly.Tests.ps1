BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-043.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdUserKerberosDesKeyOnly' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdUserKerberosDesKeyOnly {
        InModuleScope Maester { Test-MtAnssiAdUserKerberosDesKeyOnly }
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
            [bool] $DesOnly = $false,
            [AllowNull()] [Nullable[int]] $PasswordDaysAgo = 30
        )
        $passwordLastSet = $null
        if ($null -ne $PasswordDaysAgo) {
            $passwordLastSet = (Get-Date).ToUniversalTime().AddDays(-$PasswordDaysAgo)
        }
        [PSCustomObject]@{
            SamAccountName  = $Name
            Enabled         = $Enabled
            UseDESKeyOnly   = $DesOnly
            PasswordLastSet = $passwordLastSet
            LastLogonDate   = $null
        }
    }
}

Describe 'Test-MtAnssiAdUserKerberosDesKeyOnly' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict for a single account' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails for an enabled account restricted to DES'
                Enabled = $true; DesOnly = $true; Expected = $false }
            @{ Name = 'passes for an enabled account that is not restricted to DES'
                Enabled = $true; DesOnly = $false; Expected = $true }
            @{ Name = 'passes for a disabled account restricted to DES'
                Enabled = $false; DesOnly = $true; Expected = $true }
            @{ Name = 'passes for a disabled account that is not restricted to DES'
                Enabled = $false; DesOnly = $false; Expected = $true }
        ) {
            $user = Get-UserFixture -Enabled $Enabled -DesOnly $DesOnly
            $state = [PSCustomObject]@{ Users = @($user) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserKerberosDesKeyOnly | Should -Be $Expected
        }

        It 'reads only the Users category of the AD state' {
            $state = [PSCustomObject]@{ Users = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserKerberosDesKeyOnly

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Users' }
        }
    }

    Context 'several accounts' {
        BeforeEach {
            $state = [PSCustomObject]@{
                Users = @(
                    Get-UserFixture -Name 'legacyapp' -DesOnly $true -PasswordDaysAgo 400
                    Get-UserFixture -Name 'neverset' -DesOnly $true -PasswordDaysAgo $null
                    Get-UserFixture -Name 'fine'
                    Get-UserFixture -Name 'disabledflagged' -Enabled $false -DesOnly $true
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        }

        It 'fails when at least one enabled account is restricted to DES' {
            Test-MtAnssiAdUserKerberosDesKeyOnly | Should -Be $false
        }

        It 'lists only the enabled accounts restricted to DES' {
            $null = Test-MtAnssiAdUserKerberosDesKeyOnly

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'Found 2 enabled account' -and
                $Result -match 'legacyapp \| \d{4}-\d{2}-\d{2} \|' -and
                $Result -match 'neverset \| Never \|' -and
                $Result -notmatch 'fine' -and
                $Result -notmatch 'disabledflagged'
            }
        }
    }

    Context 'no account restricted to DES' {
        It 'passes and says so' {
            $state = [PSCustomObject]@{ Users = @(Get-UserFixture -Name 'fine') }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdUserKerberosDesKeyOnly | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Result -eq 'No enabled account is restricted to Kerberos DES encryption.'
            }
        }

    }

    Context 'test cannot run' {
        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdUserKerberosDesKeyOnly } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'account names come from the directory' {
        It 'escapes markdown in the account name' {
            $evil = '[click](https://evil.example)|x'
            $state = [PSCustomObject]@{ Users = @(Get-UserFixture -Name $evil -DesOnly $true) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdUserKerberosDesKeyOnly

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

        Test-MtAnssiAdUserKerberosDesKeyOnly | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
