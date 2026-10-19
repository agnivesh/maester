BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-UserFixture {
        param(
            [string] $Name = 'svc1',
            [AllowNull()] [Nullable[bool]] $Enabled = $true,
            [AllowNull()] [Nullable[bool]] $Trusted = $true
        )
        [PSCustomObject]@{
            SamAccountName       = $Name
            Enabled              = $Enabled
            TrustedForDelegation = $Trusted
            LastLogonDate        = (Get-Date).ToUniversalTime().AddDays(-3)
        }
    }

    function Get-ComputerFixture {
        param(
            [string] $Name = 'SRV1',
            [int] $PrimaryGroupId = 515,
            [AllowNull()] [Nullable[bool]] $Enabled = $true,
            [AllowNull()] [Nullable[bool]] $Trusted = $true
        )
        [PSCustomObject]@{
            DistinguishedName    = "CN=$Name,CN=Computers,DC=contoso,DC=com"
            SamAccountName       = "$Name$"
            OperatingSystem      = 'Windows Server 2022 Standard'
            PrimaryGroupId       = $PrimaryGroupId
            Enabled              = $Enabled
            TrustedForDelegation = $Trusted
            LastLogonDate        = (Get-Date).ToUniversalTime().AddDays(-3)
        }
    }

    function Find-Account {
        param([object[]] $User = @(), [object[]] $Computer = @(), [object[]] $Entry = @())
        InModuleScope Maester -Parameters @{ User = $User; Computer = $Computer; Entry = $Entry } {
            , @(Get-MtAnssiAdUnconstrainedAccount -User $User -Computer $Computer `
                    -DomainController $Entry)
        }
    }
}

Describe 'Get-MtAnssiAdUnconstrainedAccount' {
    It 'returns enabled users and computers that are trusted for delegation' {
        $result = Find-Account -User @(Get-UserFixture) -Computer @(Get-ComputerFixture)

        $result.Count | Should -Be 2
        $result[0].Type | Should -Be 'User'
        $result[0].Name | Should -Be 'svc1'
        $result[1].Type | Should -Be 'Computer'
        $result[1].Name | Should -Be 'SRV1$'
        $result[1].OperatingSystem | Should -Be 'Windows Server 2022 Standard'
        $result[1].LastLogonDate | Should -BeOfType [datetime]
    }

    It 'ignores accounts that are not trusted for delegation' {
        $result = Find-Account -User @(Get-UserFixture -Trusted $false) `
            -Computer @(Get-ComputerFixture -Trusted $false)

        $result.Count | Should -Be 0
    }

    It 'ignores accounts without a delegation state' {
        $result = Find-Account -User @(Get-UserFixture -Trusted $null) `
            -Computer @(Get-ComputerFixture -Trusted $null)

        $result.Count | Should -Be 0
    }

    It 'ignores disabled accounts and accounts without an enabled state' {
        $result = Find-Account -User @(Get-UserFixture -Enabled $false) `
            -Computer @(Get-ComputerFixture -Enabled $null)

        $result.Count | Should -Be 0
    }

    It 'ignores domain controllers found by primary group' {
        $result = Find-Account -Computer @(
            Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516
            Get-ComputerFixture -Name 'RO1' -PrimaryGroupId 521
            Get-ComputerFixture -Name 'SRV1'
        )

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'SRV1$'
    }

    It 'ignores domain controllers found by a controller entry' {
        $entry = [PSCustomObject]@{ ServerReference = 'CN=ODD,CN=Computers,DC=contoso,DC=com' }
        $result = Find-Account -Computer @(Get-ComputerFixture -Name 'ODD'; Get-ComputerFixture) `
            -Entry @($entry)

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'SRV1$'
    }

    It 'does not exclude a user whose name looks like a controller' {
        $result = Find-Account -User @(Get-UserFixture -Name 'DC1') `
            -Computer @(Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516)

        $result.Count | Should -Be 1
        $result[0].Type | Should -Be 'User'
    }

    It 'returns an empty array without accounts' {
        $result = InModuleScope Maester {
            , @(Get-MtAnssiAdUnconstrainedAccount -User $null -Computer $null `
                    -DomainController $null)
        }

        $result.Count | Should -Be 0
    }
}
