BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Get-MtAnssiAdSidRisk' {
    It '<Sid> is <Expected>' -ForEach @(
        @{ Sid = 'S-1-1-0'; Expected = 'WellKnown' }
        @{ Sid = 'S-1-5-18'; Expected = 'WellKnown' }
        @{ Sid = 'S-1-5-11'; Expected = 'WellKnown' }
        @{ Sid = 'S-1-5-32-544'; Expected = 'WellKnown' }
        @{ Sid = 'S-1-5-9'; Expected = 'WellKnown' }
        @{ Sid = 'S-1-5-80-0'; Expected = 'WellKnown' }
        @{ Sid = 'S-1-5-21-1-2-3-500'; Expected = 'PrivilegedDomain' }
        @{ Sid = 'S-1-5-21-1-2-3-502'; Expected = 'PrivilegedDomain' }
        @{ Sid = 'S-1-5-21-1-2-3-512'; Expected = 'PrivilegedDomain' }
        @{ Sid = 'S-1-5-21-1-2-3-519'; Expected = 'PrivilegedDomain' }
        @{ Sid = 'S-1-5-21-1-2-3-999'; Expected = 'PrivilegedDomain' }
        @{ Sid = 'S-1-5-21-1-2-3-0'; Expected = 'PrivilegedDomain' }
        @{ Sid = 'S-1-5-21-1111-2222-3333-519'; Expected = 'PrivilegedDomain' }
        @{ Sid = 'S-1-5-21-1-2-3-1000'; Expected = $null }
        @{ Sid = 'S-1-5-21-1-2-3-1104'; Expected = $null }
        @{ Sid = 'S-1-5-21-1-2-3-100000'; Expected = $null }
        @{ Sid = 'S-1-5-21-1-2-3'; Expected = $null }
        @{ Sid = 'S-1-5-21'; Expected = $null }
        @{ Sid = 'not a sid'; Expected = $null }
        @{ Sid = 'S-1-5-x'; Expected = $null }
        @{ Sid = ''; Expected = $null }
        @{ Sid = $null; Expected = $null }
    ) {
        $result = InModuleScope Maester -Parameters @{ Sid = $Sid } {
            Get-MtAnssiAdSidRisk -Sid $Sid
        }

        $result | Should -Be $Expected
    }
}
