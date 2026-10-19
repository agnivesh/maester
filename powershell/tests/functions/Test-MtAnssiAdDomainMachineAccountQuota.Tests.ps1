BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-076.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDomainMachineAccountQuota' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDomainMachineAccountQuota {
        InModuleScope Maester { Test-MtAnssiAdDomainMachineAccountQuota }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
}

Describe 'Test-MtAnssiAdDomainMachineAccountQuota' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict for the quota' {
        It '<Name>' -ForEach @(
            @{ Name = 'passes when the quota is 0'; Quota = 0; Expected = $true }
            @{ Name = 'fails when the quota is the default of 10'; Quota = 10; Expected = $false }
            @{ Name = 'fails when the quota is 1'; Quota = 1; Expected = $false }
            @{ Name = 'fails when the quota is raised above the default'
                Quota = 500; Expected = $false }
        ) {
            $state = [PSCustomObject]@{
                Domain = [PSCustomObject]@{ MsDsMachineAccountQuota = $Quota }
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDomainMachineAccountQuota | Should -Be $Expected
        }

        It 'fails and says the default applies when the attribute is not set' {
            $state = [PSCustomObject]@{
                Domain = [PSCustomObject]@{ MsDsMachineAccountQuota = $null }
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDomainMachineAccountQuota | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'is 10 \(the attribute is not set, so the default applies\)'
            }
        }

        It 'reads only the Domain category of the AD state' {
            $state = [PSCustomObject]@{ Domain = [PSCustomObject]@{ MsDsMachineAccountQuota = 0 } }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdDomainMachineAccountQuota

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Domain' }
        }
    }

    Context 'result text' {
        It 'says authenticated users cannot join computers when the quota is 0' {
            $state = [PSCustomObject]@{ Domain = [PSCustomObject]@{ MsDsMachineAccountQuota = 0 } }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdDomainMachineAccountQuota

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'ms-DS-MachineAccountQuota is 0: authenticated users cannot join'
            }
        }

        It 'gives the number of computers that can be joined when the quota is not 0' {
            $state = [PSCustomObject]@{ Domain = [PSCustomObject]@{ MsDsMachineAccountQuota = 3 } }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdDomainMachineAccountQuota

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'ms-DS-MachineAccountQuota is 3: any authenticated user' -and
                $Result -match 'can join up to 3 computers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the domain object is not in the collected data' {
            $state = [PSCustomObject]@{ Domain = $null }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDomainMachineAccountQuota | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain object'
            }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDomainMachineAccountQuota } | Should -Throw 'LDAP bind failed'

        }
    }
}
