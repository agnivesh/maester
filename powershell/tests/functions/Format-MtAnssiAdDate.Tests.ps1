BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Format-MtAnssiAdDate' {
    It 'formats a date as yyyy-MM-dd' {
        InModuleScope Maester {
            Format-MtAnssiAdDate -Date ([datetime]'2026-10-02T23:59:59') | Should -Be '2026-10-02'
        }
    }

    It 'returns Never for a null date' {
        InModuleScope Maester {
            Format-MtAnssiAdDate -Date $null | Should -Be 'Never'
        }
    }

    It 'returns the given text for a null date' {
        InModuleScope Maester {
            Format-MtAnssiAdDate -Date $null -NullText 'n/a' | Should -Be 'n/a'
        }
    }

    It 'accepts the date as a positional argument' {
        InModuleScope Maester {
            Format-MtAnssiAdDate ([datetime]'2020-01-05') | Should -Be '2020-01-05'
        }
    }
}
