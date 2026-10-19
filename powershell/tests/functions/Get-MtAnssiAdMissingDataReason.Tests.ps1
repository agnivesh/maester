BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Get-MtAnssiAdMissingDataReason' {
    It 'returns nothing when every collection is present' {
        $reason = InModuleScope Maester {
            $state = [PSCustomObject]@{ Users = @(1); Computers = @() }
            Get-MtAnssiAdMissingDataReason -State $state -Name 'Users', 'Computers'
        }

        $reason | Should -BeNullOrEmpty
    }

    It 'treats an empty collection as read, not as missing' {
        $reason = InModuleScope Maester {
            Get-MtAnssiAdMissingDataReason -State ([PSCustomObject]@{ Trusts = @() }) -Name 'Trusts'
        }

        $reason | Should -BeNullOrEmpty
    }

    It 'names a collection that is null' {
        $reason = InModuleScope Maester {
            Get-MtAnssiAdMissingDataReason -State ([PSCustomObject]@{ Users = $null }) -Name 'Users'
        }

        $reason | Should -Match 'Users'
    }

    It 'names a collection that is not a property of the state' {
        $reason = InModuleScope Maester {
            Get-MtAnssiAdMissingDataReason -State ([PSCustomObject]@{ Users = @() }) -Name 'Groups'
        }

        $reason | Should -Match 'Groups'
    }

    It 'names every missing collection and none of the present ones' {
        $reason = InModuleScope Maester {
            $state = [PSCustomObject]@{ Users = @(); Computers = $null; Groups = $null }
            Get-MtAnssiAdMissingDataReason -State $state -Name 'Users', 'Computers', 'Groups'
        }

        $reason | Should -Match 'Computers'
        $reason | Should -Match 'Groups'
        $reason | Should -Not -Match 'Users'
    }

    It 'says the read failed rather than that nothing exists' {
        $reason = InModuleScope Maester {
            Get-MtAnssiAdMissingDataReason -State ([PSCustomObject]@{ Users = $null }) -Name 'Users'
        }

        $reason | Should -Match 'could not be read'
    }
}
