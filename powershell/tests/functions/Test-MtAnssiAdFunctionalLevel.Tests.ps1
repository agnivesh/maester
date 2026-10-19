BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-017.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdFunctionalLevel' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdFunctionalLevel {
        InModuleScope Maester { Test-MtAnssiAdFunctionalLevel }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-StateFixture {
        param($ForestMode, $DomainMode = 'Windows2016Domain')
        [PSCustomObject]@{
            Forest = [PSCustomObject]@{ ForestMode = $ForestMode }
            Domain = [PSCustomObject]@{ DomainMode = $DomainMode }
        }
    }
}

Describe 'Test-MtAnssiAdFunctionalLevel' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    # ANSSI: grade 1 below level 4, grade 3 below level 6, grade 4 below level 7.
    Context 'forest functional level and the severity it gets' {
        It '<Mode> fails' -ForEach @(
            @{ Mode = 'Windows2000Forest' }
            @{ Mode = 'Windows2003InterimForest' }
            @{ Mode = 'Windows2003Forest' }
            @{ Mode = 'Windows2008Forest' }
            @{ Mode = 'Windows2008R2Forest' }
            @{ Mode = 'Windows2012Forest' }
            @{ Mode = 'Windows2012R2Forest' }
        ) {
            $state = Get-StateFixture -ForestMode $Mode
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdFunctionalLevel | Should -Be $false
        }

        It '<Mode> passes' -ForEach @(
            @{ Mode = 'Windows2016Forest' }
            @{ Mode = 8 }
            @{ Mode = 10 }
        ) {
            $state = Get-StateFixture -ForestMode $Mode
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdFunctionalLevel | Should -BeTrue
        }

        It 'reports the severity <Expected> to Maester for <Mode>' -ForEach @(
            @{ Mode = 'Windows2000Forest'; Expected = 'Critical' }
            @{ Mode = 'Windows2003InterimForest'; Expected = 'Critical' }
            @{ Mode = 'Windows2003Forest'; Expected = 'Critical' }
            @{ Mode = 'Windows2008Forest'; Expected = 'Critical' }
            @{ Mode = 'Windows2008R2Forest'; Expected = 'Medium' }
            @{ Mode = 'Windows2012Forest'; Expected = 'Medium' }
            @{ Mode = 'Windows2012R2Forest'; Expected = 'Low' }
        ) {
            $state = Get-StateFixture -ForestMode $Mode
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
            # The filter runs in the module, so the expected value is written into it as a literal.
            $filter = [scriptblock]::Create("`$Severity -eq '$Expected'")

            $null = Test-MtAnssiAdFunctionalLevel

            Should -Invoke @detail -ParameterFilter $filter
        }

        It 'reports the most severe severity when the test passes' {
            $state = Get-StateFixture -ForestMode 'Windows2016Forest'
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdFunctionalLevel

            Should -Invoke @detail -ParameterFilter { $Severity -eq 'Critical' }
        }

        It 'reads the Forest and Domain categories of the AD state' {
            $state = Get-StateFixture -ForestMode 'Windows2016Forest'
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdFunctionalLevel

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Forest' -and
                $Categories -contains 'Domain'
            }
        }
    }

    Context 'result text' {
        It 'names the forest level, its number and the severity in a table' {
            $state = Get-StateFixture -ForestMode 'Windows2008R2Forest' `
                -DomainMode 'Windows2012R2Domain'
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdFunctionalLevel

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'forest functional level is Windows Server 2008 R2 \(level 4\)' -and
                $Result -match 'Forest \| Windows Server 2008 R2 \| 4 \| Medium \|'
            }
        }

        It 'gives the functional level of the domain for information' {
            $state = Get-StateFixture -ForestMode 'Windows2008Forest' `
                -DomainMode 'Windows2012R2Domain'
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdFunctionalLevel

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'domain is Windows Server 2012 R2 \(level 6\)'
            }
        }

        It 'leaves out the domain sentence when the domain level is unknown' {
            $state = Get-StateFixture -ForestMode 'Windows2008Forest' -DomainMode $null
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdFunctionalLevel

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch 'functional level of the domain'
            }
        }

        It 'says Windows Server 2016 or later for a passing level' {
            $state = Get-StateFixture -ForestMode 10
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdFunctionalLevel

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'Windows Server 2016 or later \(level 10\)\.$'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when <Name>' -ForEach @(
            @{ Name = 'the forest mode is missing'; Mode = $null }
            @{ Name = 'the forest mode is not recognized'; Mode = 'WindowsFutureForest' }
        ) {
            $state = Get-StateFixture -ForestMode $Mode
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdFunctionalLevel | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match 'forest functional level'
            }
        }

        It 'is skipped when the forest object is missing' {
            $state = [PSCustomObject]@{ Forest = $null; Domain = $null }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdFunctionalLevel | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdFunctionalLevel } | Should -Throw 'LDAP bind failed'

        }
    }
}
