BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-016.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDsHeuristicsDangerousValue' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDsHeuristicsDangerousValue {
        InModuleScope Maester { Test-MtAnssiAdDsHeuristicsDangerousValue }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    # ANSSI's hardened value: every setting at its default except BlockOwnerImplicitRights and
    # AttributeAuthorizationOnLDAPAdd, which are explicitly 1.
    $script:clean = '0000000001000000000200000001130'

    function Get-DsHeuristicsValue {
        param([hashtable] $Override = @{})
        $characters = $script:clean.ToCharArray()
        foreach ($position in $Override.Keys) {
            $characters[$position - 1] = ([string]$Override[$position])[0]
        }
        -join $characters
    }

    function Get-StateFixture {
        param([AllowNull()] [string] $Value)
        [PSCustomObject]@{ Configuration = [PSCustomObject]@{ DsHeuristics = $Value } }
    }
}

Describe 'Test-MtAnssiAdDsHeuristicsDangerousValue' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict and severity' {
        It 'passes for the hardened value and reports the most severe severity' {
            $state = Get-StateFixture -Value $script:clean
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDsHeuristicsDangerousValue | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Severity -eq 'Critical' -and $Result -match 'holds no dangerous setting'
            }
        }

        It '<Name> fails with severity <Expected>' -ForEach @(
            @{ Name = 'an unset attribute'; Value = $null; Expected = 'Low' }
            @{ Name = 'an empty attribute'; Value = ''; Expected = 'Low' }
            @{ Name = 'fAllowAnonNSPI = 1'; Position = 8; Character = '1'; Expected = 'Critical' }
            @{ Name = 'dwAdminSDExMask = a'; Position = 16; Character = 'a'; Expected = 'Critical' }
            @{ Name = 'fLDAPBlockAnonOps = 2'; Position = 7; Character = '2'; Expected = 'High' }
            @{ Name = 'DoNotVerifyUPNAndOrSPNUniqueness = 1'; Position = 21; Character = '1'
                Expected = 'High' }
            @{ Name = 'AttributeAuthorizationOnLDAPAdd = 2'; Position = 28; Character = '2'
                Expected = 'High' }
            @{ Name = 'BlockOwnerImplicitRights = 2'; Position = 29; Character = '2'
                Expected = 'High' }
            @{ Name = 'DisableConfidentialAttributeEncryptionRequirements = 1'; Position = 31
                Character = '1'; Expected = 'High' }
            @{ Name = 'AttributeAuthorizationOnLDAPAdd = 0'; Position = 28; Character = '0'
                Expected = 'Low' }
            @{ Name = 'BlockOwnerImplicitRights = 0'; Position = 29; Character = '0'
                Expected = 'Low' }
        ) {
            $dsHeuristics = $Value
            if ($null -ne $Position) {
                $dsHeuristics = Get-DsHeuristicsValue -Override @{ $Position = $Character }
            }
            $state = Get-StateFixture -Value $dsHeuristics
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
            # The filter runs in the module, so the expected value is written into it as a literal.
            $filter = [scriptblock]::Create("`$Severity -eq '$Expected'")

            Test-MtAnssiAdDsHeuristicsDangerousValue | Should -Be $false

            Should -Invoke @detail -ParameterFilter $filter
        }

        It 'reports the most severe severity when several settings are dangerous' {
            $value = Get-DsHeuristicsValue -Override @{ 8 = '1'; 29 = '0' }
            $state = Get-StateFixture -Value $value
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDsHeuristicsDangerousValue | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Severity -eq 'Critical' -and
                $Result -match 'fAllowAnonNSPI \| 8 \| 1 \| 0 \| Critical' -and
                $Result -match 'BlockOwnerImplicitRights \| 29 \| 0 \| 1 \| Low'
            }
        }

        It 'reads only the Configuration category of the AD state' {
            $state = Get-StateFixture -Value $script:clean
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdDsHeuristicsDangerousValue

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 1 -and $Categories -contains 'Configuration'
            }
        }
    }

    Context 'result text' {
        It 'gives the number of settings, the current value and the recommended values' {
            $value = Get-DsHeuristicsValue -Override @{ 7 = '2' }
            $state = Get-StateFixture -Value $value
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdDsHeuristicsDangerousValue

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'Found 1 dangerous dSHeuristics setting\(s\)' -and
                $Result -match 'current value of the attribute is 0000002' -and
                $Result -match 'fLDAPBlockAnonOps \| 7 \| 2 \| not 2 \| High'
            }
        }

        It 'says the attribute is not set when it has no value' {
            $state = Get-StateFixture -Value $null
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdDsHeuristicsDangerousValue

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'current value of the attribute is not set' -and
                $Result -match 'AttributeAuthorizationOnLDAPAdd \| 28 \| not set \| 1 \| Low'
            }
        }

        It 'escapes markdown in the current value' {
            $state = Get-StateFixture -Value '[click](https://evil.example)|x'
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdDsHeuristicsDangerousValue

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the directory configuration is missing' {
            $state = [PSCustomObject]@{ Configuration = $null }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDsHeuristicsDangerousValue | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'configuration'
            }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDsHeuristicsDangerousValue } | Should -Throw 'LDAP bind failed'

        }
    }
}
