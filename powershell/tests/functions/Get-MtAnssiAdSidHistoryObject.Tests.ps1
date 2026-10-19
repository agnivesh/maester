BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-ItemFixture {
        param([string] $Name = 'alice', [object[]] $SidHistory = @())
        [PSCustomObject]@{
            SamAccountName = $Name
            SidHistory     = $SidHistory
            LastLogonDate  = [datetime]'2026-09-01'
        }
    }

    function Find-Object {
        param([object[]] $User, [object[]] $Computer, [object[]] $Group)
        InModuleScope Maester -Parameters @{ U = $User; C = $Computer; G = $Group } {
            , @(Get-MtAnssiAdSidHistoryObject -User $U -Computer $C -Group $G)
        }
    }
}

Describe 'Get-MtAnssiAdSidHistoryObject' {
    It 'returns users, computers and groups that have a SID history, with their type' {
        $user = Get-ItemFixture -Name 'u1' -SidHistory @('S-1-5-21-1-2-3-1104')
        $computer = Get-ItemFixture -Name 'c1$' -SidHistory @('S-1-5-21-1-2-3-1105')
        $group = Get-ItemFixture -Name 'g1' -SidHistory @('S-1-5-21-1-2-3-1106')
        $result = Find-Object -User @($user) -Computer @($computer) -Group @($group)

        $result.Count | Should -Be 3
        $result[0].Type | Should -Be 'User'
        $result[0].Name | Should -Be 'u1'
        $result[1].Type | Should -Be 'Computer'
        $result[2].Type | Should -Be 'Group'
        $result[2].SidHistory | Should -Be 'S-1-5-21-1-2-3-1106'
    }

    It 'ignores objects with an empty SID history' {
        $result = Find-Object -User @(
            Get-ItemFixture -Name 'none'
            Get-ItemFixture -Name 'null' -SidHistory $null
            Get-ItemFixture -Name 'has' -SidHistory @('S-1-5-21-1-2-3-1104')
        ) -Computer @() -Group @()

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'has'
    }

    It 'keeps every value of a SID history' {
        $values = @('S-1-5-21-1-2-3-1104', 'S-1-5-21-4-5-6-1104')
        $result = Find-Object -User @(Get-ItemFixture -SidHistory $values) -Computer @() -Group @()

        $result.Count | Should -Be 1
        $result[0].SidHistory.Count | Should -Be 2
        $result[0].SidHistory[1] | Should -Be 'S-1-5-21-4-5-6-1104'
    }

    It 'keeps the last logon of the object' {
        $user = Get-ItemFixture -SidHistory @('S-1-1-0')
        $result = Find-Object -User @($user) -Computer @() -Group @()

        $result[0].LastLogonDate | Should -Be ([datetime]'2026-09-01')
    }

    It 'reads SIDs that are objects with a Value property' {
        $sid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1104' }
        $result = Find-Object -User @(Get-ItemFixture -SidHistory @($sid)) -Computer @() -Group @()

        $result[0].SidHistory[0] | Should -Be 'S-1-5-21-1-2-3-1104'
        $result[0].SidHistory[0] | Should -BeOfType [string]
    }

    It 'reads SIDs given as a single text value' {
        $user = Get-ItemFixture
        $user.SidHistory = 'S-1-5-21-1-2-3-1104'
        $result = Find-Object -User @($user) -Computer @() -Group @()

        $result[0].SidHistory | Should -Be 'S-1-5-21-1-2-3-1104'
    }

    It 'returns an empty array without data' {
        $result = Find-Object -User $null -Computer $null -Group $null

        $result.Count | Should -Be 0
    }
}
