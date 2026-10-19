BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'ConvertTo-MtAnssiAdFunctionalLevel' {
    It 'converts the forest mode <Mode> to <Expected>' -ForEach @(
        @{ Mode = 'Windows2000Forest'; Expected = 0 }
        @{ Mode = 'Windows2003InterimForest'; Expected = 1 }
        @{ Mode = 'Windows2003Forest'; Expected = 2 }
        @{ Mode = 'Windows2008Forest'; Expected = 3 }
        @{ Mode = 'Windows2008R2Forest'; Expected = 4 }
        @{ Mode = 'Windows2012Forest'; Expected = 5 }
        @{ Mode = 'Windows2012R2Forest'; Expected = 6 }
        @{ Mode = 'Windows2016Forest'; Expected = 7 }
    ) {
        InModuleScope Maester -Parameters @{ Mode = $Mode } {
            ConvertTo-MtAnssiAdFunctionalLevel -Mode $Mode
        } | Should -Be $Expected
    }

    It 'converts the domain mode <Mode> to <Expected>' -ForEach @(
        @{ Mode = 'Windows2000Domain'; Expected = 0 }
        @{ Mode = 'Windows2003InterimDomain'; Expected = 1 }
        @{ Mode = 'Windows2008R2Domain'; Expected = 4 }
        @{ Mode = 'Windows2016Domain'; Expected = 7 }
    ) {
        InModuleScope Maester -Parameters @{ Mode = $Mode } {
            ConvertTo-MtAnssiAdFunctionalLevel -Mode $Mode
        } | Should -Be $Expected
    }

    It 'returns the number itself for a newer level (<Mode>)' -ForEach @(
        @{ Mode = 8; Expected = 8 }
        @{ Mode = 10; Expected = 10 }
        @{ Mode = '10'; Expected = 10 }
    ) {
        InModuleScope Maester -Parameters @{ Mode = $Mode } {
            ConvertTo-MtAnssiAdFunctionalLevel -Mode $Mode
        } | Should -Be $Expected
    }

    It 'returns nothing for <Name>' -ForEach @(
        @{ Name = 'a null mode'; Mode = $null }
        @{ Name = 'an empty text'; Mode = '' }
        @{ Name = 'an unknown name'; Mode = 'WindowsFutureForest' }
        @{ Name = 'a negative number'; Mode = -1 }
    ) {
        $result = InModuleScope Maester -Parameters @{ Mode = $Mode } {
            ConvertTo-MtAnssiAdFunctionalLevel -Mode $Mode
        }

        $result | Should -BeNullOrEmpty
    }
}
