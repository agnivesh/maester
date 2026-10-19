BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-055.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdTrustAccountPasswordAge' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdTrustAccountPasswordAge {
        InModuleScope Maester { Test-MtAnssiAdTrustAccountPasswordAge }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-AccountFixture {
        param(
            [string] $Name,
            [AllowNull()] [Nullable[int]] $DaysAgo,
            [int] $Uac = 0x820,
            [string] $DistinguishedName = "CN=$Name,CN=Users,DC=contoso,DC=com"
        )
        $lastSet = $null
        if ($null -ne $DaysAgo) { $lastSet = (Get-Date).ToUniversalTime().AddDays(-$DaysAgo) }
        [PSCustomObject]@{
            SamAccountName     = $Name
            DistinguishedName  = $DistinguishedName
            UserAccountControl = $Uac
            PasswordLastSet    = $lastSet
        }
    }
}

Describe 'Test-MtAnssiAdTrustAccountPasswordAge' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    # Uac: 0x820 interdomain trust account, 0x822 the same but disabled, 0x200 regular user.
    Context 'verdict for a single account' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails for a trust account unchanged for more than a year'
                Uac = 0x820; DaysAgo = 370; Expected = $false }
            @{ Name = 'fails for a trust account whose password was never set'
                Uac = 0x820; DaysAgo = $null; Expected = $false }
            @{ Name = 'fails for a disabled trust account with an old password'
                Uac = 0x822; DaysAgo = 370; Expected = $false }
            @{ Name = 'passes for a trust account changed within the year'
                Uac = 0x820; DaysAgo = 360; Expected = $true }
            @{ Name = 'passes for a trust account changed today'
                Uac = 0x820; DaysAgo = 0; Expected = $true }
            @{ Name = 'ignores a regular user with an old password'
                Uac = 0x200; DaysAgo = 3000; Expected = $true }
            @{ Name = 'ignores a regular user whose password was never set'
                Uac = 0x200; DaysAgo = $null; Expected = $true }
        ) {
            $state = [PSCustomObject]@{
                Users = @(Get-AccountFixture -Name 'TRUST$' -DaysAgo $DaysAgo -Uac $Uac)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustAccountPasswordAge | Should -Be $Expected
        }

        It 'reads only the Users category of the AD state' {
            $state = [PSCustomObject]@{ Users = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdTrustAccountPasswordAge

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Users' }
        }
    }

    Context 'several accounts' {
        BeforeEach {
            $state = [PSCustomObject]@{
                Users = @(
                    Get-AccountFixture -Name 'OLD$' -DaysAgo 400
                    Get-AccountFixture -Name 'FRESH$' -DaysAgo 10
                    Get-AccountFixture -Name 'regular' -DaysAgo 4000 -Uac 0x200
                    Get-AccountFixture -Name 'NEVER$' -DaysAgo $null
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        }

        It 'fails when at least one trust account is stale' {
            Test-MtAnssiAdTrustAccountPasswordAge | Should -Be $false
        }

        It 'lists only the stale trust accounts' {
            $null = Test-MtAnssiAdTrustAccountPasswordAge

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'Found 2 trust account' -and
                $Result -match 'OLD\$ \| \d{4}-\d{2}-\d{2} \|' -and
                $Result -match 'NEVER\$ \| Never \|' -and
                $Result -notmatch 'FRESH' -and
                $Result -notmatch 'regular'
            }
        }

        It 'shows the distinguished name of the account' {
            $null = Test-MtAnssiAdTrustAccountPasswordAge

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'CN=OLD\$,CN=Users,DC=contoso,DC=com'
            }
        }
    }

    Context 'no trust account' {
        It 'passes and says so when the user list is empty' {
            $state = [PSCustomObject]@{ Users = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustAccountPasswordAge | Should -BeTrue

            Should -Invoke @detail -ParameterFilter { $Result -match 'No trust account was found' }
        }

        It 'says all passwords are recent when every trust account is fresh' {
            $state = [PSCustomObject]@{ Users = @(Get-AccountFixture -Name 'FRESH$' -DaysAgo 10) }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustAccountPasswordAge | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'every trust account was changed within the last year'
            }
        }
    }

    Context 'test cannot run' {
        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdTrustAccountPasswordAge } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'account names come from the directory' {
        It 'escapes markdown in the account name and distinguished name' {
            $evil = '[click](https://evil.example)|x'
            $state = [PSCustomObject]@{
                Users = @(Get-AccountFixture -Name $evil -DaysAgo 400 -DistinguishedName $evil)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdTrustAccountPasswordAge

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

        Test-MtAnssiAdTrustAccountPasswordAge | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
