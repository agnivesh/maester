BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Find-Dangerous {
        param([object[]] $Object)
        InModuleScope Maester -Parameters @{ Object = $Object } {
            , @(Get-MtAnssiAdDangerousSidHistory -Object $Object)
        }
    }

    function Get-ObjectFixture {
        param([string] $Name = 'alice', [string[]] $SidHistory = @())
        [PSCustomObject]@{
            Type          = 'User'
            Name          = $Name
            SidHistory    = $SidHistory
            LastLogonDate = [datetime]'2026-09-01'
        }
    }
}

Describe 'Get-MtAnssiAdDangerousSidHistory' {
    It 'returns nothing for ordinary migrated SIDs' {
        $objects = @(Get-ObjectFixture -SidHistory @('S-1-5-21-1-2-3-1104', 'S-1-5-21-1-2-3-5000'))

        (Find-Dangerous -Object $objects).Count | Should -Be 0
    }

    It 'returns each dangerous SID of an object with its risk' {
        $history = @('S-1-5-21-1-2-3-1104', 'S-1-5-21-1-2-3-519', 'S-1-5-32-544')
        $result = Find-Dangerous -Object @(Get-ObjectFixture -Name 'bob' -SidHistory $history)

        $result.Count | Should -Be 2
        $result[0].Sid | Should -Be 'S-1-5-21-1-2-3-519'
        $result[0].Risk | Should -Be 'PrivilegedDomain'
        $result[1].Sid | Should -Be 'S-1-5-32-544'
        $result[1].Risk | Should -Be 'WellKnown'
        $result[0].Name | Should -Be 'bob'
        $result[0].Type | Should -Be 'User'
        $result[0].LastLogonDate | Should -Be ([datetime]'2026-09-01')
    }

    It 'keeps the objects apart' {
        $result = Find-Dangerous -Object @(
            Get-ObjectFixture -Name 'a' -SidHistory @('S-1-1-0')
            Get-ObjectFixture -Name 'b' -SidHistory @('S-1-5-21-1-2-3-1104')
            Get-ObjectFixture -Name 'c' -SidHistory @('S-1-5-18')
        )

        $result.Count | Should -Be 2
        $result[0].Name | Should -Be 'a'
        $result[1].Name | Should -Be 'c'
    }

    It 'returns an empty array without objects' {
        (Find-Dangerous -Object @()).Count | Should -Be 0
    }
}
