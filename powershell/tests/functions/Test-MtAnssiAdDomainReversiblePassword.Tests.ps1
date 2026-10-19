BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-064.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDomainReversiblePassword' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDomainReversiblePassword {
        InModuleScope Maester { Test-MtAnssiAdDomainReversiblePassword }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Use-Domain {
        param([AllowNull()] [object] $PwdProperties)
        $state = [PSCustomObject]@{
            Domain = [PSCustomObject]@{ PwdProperties = $PwdProperties }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDomainReversiblePassword' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict for pwdProperties' {
        It '<Value> <Name>' -ForEach @(
            @{ Value = 0; Name = 'passes: the default'; Expected = $true }
            @{ Value = 1; Name = 'passes: complexity only'; Expected = $true }
            @{ Value = 15; Name = 'passes: every flag below 16'; Expected = $true }
            @{ Value = 32; Name = 'passes: refuse password change only'; Expected = $true }
            @{ Value = 47; Name = 'passes: every flag but 16'; Expected = $true }
            @{ Value = 16; Name = 'fails: cleartext only'; Expected = $false }
            @{ Value = 17; Name = 'fails: cleartext and complexity'; Expected = $false }
            @{ Value = 48; Name = 'fails: cleartext and refuse change'; Expected = $false }
            @{ Value = 63; Name = 'fails: every flag'; Expected = $false }
        ) {
            Use-Domain -PwdProperties $Value

            Test-MtAnssiAdDomainReversiblePassword | Should -Be $Expected
        }

        It 'reads a value stored as text' {
            Use-Domain -PwdProperties '16'

            Test-MtAnssiAdDomainReversiblePassword | Should -Be $false
        }
    }

    Context 'result text' {
        It 'gives the value when the test passes' {
            Use-Domain -PwdProperties 1

            $null = Test-MtAnssiAdDomainReversiblePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'is 1: it does not have the DOMAIN_PASSWORD_STORE_CLEARTEXT flag'
            }
        }

        It 'gives the value and says the passwords stay recoverable when the test fails' {
            Use-Domain -PwdProperties 17

            $null = Test-MtAnssiAdDomainReversiblePassword

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'is 17 and has the DOMAIN_PASSWORD_STORE_CLEARTEXT flag' -and
                $Result -match 'stay recoverable until they are changed'
            }
        }
    }

    Context 'data requested' {
        It 'reads only the Domain category' {
            Use-Domain -PwdProperties 0

            $null = Test-MtAnssiAdDomainReversiblePassword

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Domain' }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when pwdProperties is not set' {
            Use-Domain -PwdProperties $null

            Test-MtAnssiAdDomainReversiblePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'pwdProperties'
            }
        }

        It 'is skipped when the domain object is missing' {
            $state = [PSCustomObject]@{ Domain = $null }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDomainReversiblePassword | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDomainReversiblePassword } | Should -Throw 'LDAP bind failed'

        }
    }
}
