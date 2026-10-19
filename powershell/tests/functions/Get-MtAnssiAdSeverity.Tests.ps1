BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Get-MtAnssiAdSeverity' {
    It 'maps grade <Grade> to <Expected>' -ForEach @(
        @{ Grade = 1; Expected = 'Critical' }
        @{ Grade = 2; Expected = 'High' }
        @{ Grade = 3; Expected = 'Medium' }
        @{ Grade = 4; Expected = 'Low' }
    ) {
        InModuleScope Maester -Parameters @{ Grade = $Grade } {
            Get-MtAnssiAdSeverity -Grade $Grade
        } | Should -Be $Expected
    }

    It 'returns the severity of the most severe grade when several are given' {
        InModuleScope Maester {
            Get-MtAnssiAdSeverity -Grade 4, 2, 3
        } | Should -Be 'High'
    }

    It 'accepts the same grade several times' {
        InModuleScope Maester {
            Get-MtAnssiAdSeverity -Grade 4, 4, 4
        } | Should -Be 'Low'
    }

    It 'rejects grade <Grade>' -ForEach @(
        @{ Grade = 0 }
        @{ Grade = 5 }
        @{ Grade = -1 }
    ) {
        InModuleScope Maester -Parameters @{ Grade = $Grade } {
            { Get-MtAnssiAdSeverity -Grade $Grade } | Should -Throw
        }
    }

    It 'rejects a list that contains an invalid grade' {
        InModuleScope Maester {
            { Get-MtAnssiAdSeverity -Grade 1, 7 } | Should -Throw
        }
    }

    It 'requires a grade' {
        InModuleScope Maester {
            { Get-MtAnssiAdSeverity -Grade @() } | Should -Throw
        }
    }
}
