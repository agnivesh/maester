BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-ComputerFixture {
        param(
            [string] $Name = 'SRV1',
            [AllowNull()] [Nullable[bool]] $Enabled = $true,
            [AllowNull()] [Nullable[int]] $PasswordDaysAgo = 10,
            [AllowNull()] [Nullable[int]] $LogonDaysAgo = 1
        )
        $now = (Get-Date).ToUniversalTime()
        $passwordLastSet = $null
        if ($null -ne $PasswordDaysAgo) { $passwordLastSet = $now.AddDays(-$PasswordDaysAgo) }
        $lastLogon = $null
        if ($null -ne $LogonDaysAgo) { $lastLogon = $now.AddDays(-$LogonDaysAgo) }
        [PSCustomObject]@{
            Name            = $Name
            Enabled         = $Enabled
            PasswordLastSet = $passwordLastSet
            LastLogonDate   = $lastLogon
        }
    }

    function Find-Stale {
        param([object[]] $Computer, [string] $Attribute, [switch] $NullIsStale)
        InModuleScope Maester -Parameters @{
            Computer = $Computer; Attribute = $Attribute; NullIsStale = $NullIsStale
        } {
            $cutoff = (Get-Date).ToUniversalTime().AddDays(-45)
            Get-MtAnssiAdStaleComputer -Computer $Computer -Attribute $Attribute `
                -Cutoff $cutoff -NullIsStale:$NullIsStale
        }
    }
}

Describe 'Get-MtAnssiAdStaleComputer' {
    It 'returns the computers whose date is before the cutoff' {
        $result = Find-Stale -Attribute PasswordLastSet -Computer @(
            Get-ComputerFixture -Name 'NEW' -PasswordDaysAgo 44
            Get-ComputerFixture -Name 'OLD' -PasswordDaysAgo 46
        )

        $result.EnabledCount | Should -Be 2
        @($result.Stale).Count | Should -Be 1
        $result.Stale[0].Computer.Name | Should -Be 'OLD'
    }

    It 'does not treat a date equal to the cutoff as stale' {
        $result = InModuleScope Maester {
            $cutoff = [datetime]::new(2026, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
            $computer = [PSCustomObject]@{
                Name = 'SRV1'; Enabled = $true; PasswordLastSet = $cutoff
            }
            Get-MtAnssiAdStaleComputer -Computer @($computer) `
                -Attribute PasswordLastSet -Cutoff $cutoff
        }

        @($result.Stale).Count | Should -Be 0
    }

    It 'keeps the computer account and the date of a stale computer' {
        $computer = Get-ComputerFixture -Name 'OLD' -PasswordDaysAgo 100

        $result = Find-Stale -Attribute PasswordLastSet -Computer @($computer)

        $result.Stale[0].Computer | Should -Be $computer
        $result.Stale[0].Date | Should -Be $computer.PasswordLastSet
    }

    It 'reads the attribute that was asked for' {
        $computer = Get-ComputerFixture -PasswordDaysAgo 100 -LogonDaysAgo 1

        @((Find-Stale -Attribute PasswordLastSet -Computer @($computer)).Stale).Count |
            Should -Be 1
        @((Find-Stale -Attribute LastLogonDate -Computer @($computer)).Stale).Count |
            Should -Be 0
    }

    It 'skips and does not count disabled computers and computers without a state' {
        $result = Find-Stale -Attribute PasswordLastSet -Computer @(
            Get-ComputerFixture -Name 'OFF' -Enabled $false -PasswordDaysAgo 100
            Get-ComputerFixture -Name 'UNKNOWN' -Enabled $null -PasswordDaysAgo 100
            Get-ComputerFixture -Name 'ON' -PasswordDaysAgo 100
        )

        $result.EnabledCount | Should -Be 1
        @($result.Stale).Count | Should -Be 1
        $result.Stale[0].Computer.Name | Should -Be 'ON'
    }

    It 'treats a missing date as stale only when NullIsStale is set' {
        $computer = Get-ComputerFixture -PasswordDaysAgo $null

        $strict = Find-Stale -Attribute PasswordLastSet -Computer @($computer) -NullIsStale
        $lenient = Find-Stale -Attribute PasswordLastSet -Computer @($computer)

        @($strict.Stale).Count | Should -Be 1
        @($lenient.Stale).Count | Should -Be 0
    }

    It 'returns nothing for an empty list' {
        $result = Find-Stale -Attribute PasswordLastSet -Computer @()

        $result.EnabledCount | Should -Be 0
        @($result.Stale).Count | Should -Be 0
    }
}
