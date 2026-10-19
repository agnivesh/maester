BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:base = @('top', 'person', 'organizationalPerson', 'user', 'computer')

    function Get-ComputerFixture {
        param([string] $Name = 'acct$', [AllowNull()] [string[]] $Extra = @())
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=Managed Service Accounts,DC=contoso,DC=com"
            Name              = $Name
            Enabled           = $true
            PasswordLastSet   = [datetime]'2026-01-02'
            LastLogonDate     = [datetime]'2026-01-03'
            ObjectClass       = @($script:base) + @($Extra | Where-Object { $_ })
        }
    }

    function Get-Account {
        param([AllowNull()] [object[]] $Computer)
        InModuleScope Maester -Parameters @{ Computer = $Computer } {
            param($Computer)
            Get-MtAnssiAdManagedServiceAccount -Computer $Computer
        }
    }
}

Describe 'Get-MtAnssiAdManagedServiceAccount' {
    It 'returns a group managed service account as gMSA' {
        $result = @(Get-Account -Computer @(
                Get-ComputerFixture -Extra 'msDS-GroupManagedServiceAccount'))

        $result.Count | Should -Be 1
        $result[0].Type | Should -BeExactly 'gMSA'
    }

    It 'returns a standalone managed service account as MSA' {
        $result = @(Get-Account -Computer @(
                Get-ComputerFixture -Extra 'msDS-ManagedServiceAccount'))

        $result[0].Type | Should -BeExactly 'MSA'
    }

    It 'does not return ordinary computers or delegated managed service accounts' {
        $result = @(Get-Account -Computer @(
                (Get-ComputerFixture -Name 'PC1$')
                (Get-ComputerFixture -Name 'd1$' -Extra 'msDS-DelegatedManagedServiceAccount')
            ))

        $result.Count | Should -Be 0
    }

    It 'returns nothing for null or empty input' {
        @(Get-Account -Computer $null).Count | Should -Be 0
        @(Get-Account -Computer @()).Count | Should -Be 0
    }

    It 'skips a computer without object classes' {
        $computer = Get-ComputerFixture
        $computer.ObjectClass = $null

        @(Get-Account -Computer @($computer)).Count | Should -Be 0
    }

    It 'keeps the properties the date checks need' {
        $result = @(Get-Account -Computer @(
                Get-ComputerFixture -Name 'g1$' -Extra 'msDS-GroupManagedServiceAccount'))

        $result[0].Name | Should -Be 'g1$'
        $result[0].DistinguishedName |
            Should -Be 'CN=g1$,CN=Managed Service Accounts,DC=contoso,DC=com'
        $result[0].Enabled | Should -Be $true
        $result[0].PasswordLastSet | Should -Be ([datetime]'2026-01-02')
        $result[0].LastLogonDate | Should -Be ([datetime]'2026-01-03')
    }

    It 'returns gMSAs and MSAs together in input order' {
        $result = @(Get-Account -Computer @(
                (Get-ComputerFixture -Name 'm1$' -Extra 'msDS-ManagedServiceAccount')
                (Get-ComputerFixture -Name 'PC1$')
                (Get-ComputerFixture -Name 'g1$' -Extra 'msDS-GroupManagedServiceAccount')
            ))

        ($result | ForEach-Object { $_.Name }) -join ',' | Should -Be 'm1$,g1$'
    }
}
