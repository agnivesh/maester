BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-UserFixture {
        param([string] $Sam = 'krbtgt_12345', [string] $Name = $Sam, [string] $Dn = $null)
        if (-not $Dn) { $Dn = "CN=$Name,CN=Users,DC=contoso,DC=com" }
        [PSCustomObject]@{
            DistinguishedName = $Dn
            Name              = $Name
            SamAccountName    = $Sam
            Enabled           = $false
            Created           = [datetime]'2024-05-06'
            PasswordLastSet   = [datetime]'2024-05-07'
        }
    }

    function Get-ComputerFixture {
        param([string] $Name = 'RODC1$', [AllowNull()] [string] $Link = $null)
        [PSCustomObject]@{ Name = $Name; KrbTgtLink = $Link }
    }

    function Get-Krbtgt {
        param([AllowNull()] [object[]] $User, [AllowNull()] [object[]] $Computer)
        InModuleScope Maester -Parameters @{ User = $User; Computer = $Computer } {
            param($User, $Computer)
            Get-MtAnssiAdRodcKrbtgt -User $User -Computer $Computer
        }
    }
}

Describe 'Get-MtAnssiAdRodcKrbtgt' {
    Context 'which accounts are returned' {
        It 'returns the krbtgt accounts of RODCs' {
            $result = @(Get-Krbtgt -User @(Get-UserFixture -Sam 'krbtgt_12345') -Computer @())

            $result.Count | Should -Be 1
            $result[0].SamAccountName | Should -Be 'krbtgt_12345'
        }

        It 'does not return the built-in krbtgt account or other users' {
            $result = @(Get-Krbtgt -User @(
                    (Get-UserFixture -Sam 'krbtgt')
                    (Get-UserFixture -Sam 'alice')
                    (Get-UserFixture -Sam 'xkrbtgt_1')
                ) -Computer @())

            $result.Count | Should -Be 0
        }

        It 'matches the name without regard to case and with any suffix' {
            $result = @(Get-Krbtgt -User @(
                    (Get-UserFixture -Sam 'KRBTGT_999')
                    (Get-UserFixture -Sam 'krbtgt_AzureAD')
                ) -Computer @())

            $result.Count | Should -Be 2
        }

        It 'returns nothing for null or empty input' {
            @(Get-Krbtgt -User $null -Computer $null).Count | Should -Be 0
            @(Get-Krbtgt -User @() -Computer @()).Count | Should -Be 0
        }
    }

    Context 'orphans' {
        It 'is not an orphan when a computer points to the account' {
            $user = Get-UserFixture -Sam 'krbtgt_12345'
            $result = @(Get-Krbtgt -User @($user) -Computer @(
                    Get-ComputerFixture -Name 'RODC1$' -Link $user.DistinguishedName))

            $result[0].IsOrphan | Should -Be $false
            $result[0].Computer | Should -Be 'RODC1$'
        }

        It 'is an orphan when no computer points to the account' {
            $result = @(Get-Krbtgt -User @(Get-UserFixture) -Computer @(
                    Get-ComputerFixture -Name 'PC1$' -Link $null))

            $result[0].IsOrphan | Should -Be $true
            $null -eq $result[0].Computer | Should -Be $true
        }

        It 'is an orphan when the computers point to another account' {
            $result = @(Get-Krbtgt -User @(Get-UserFixture -Sam 'krbtgt_1') -Computer @(
                    Get-ComputerFixture -Link 'CN=krbtgt_2,CN=Users,DC=contoso,DC=com'))

            $result[0].IsOrphan | Should -Be $true
        }

        It 'compares distinguished names without regard to case' {
            $user = Get-UserFixture -Sam 'krbtgt_12345'
            $result = @(Get-Krbtgt -User @($user) -Computer @(
                    Get-ComputerFixture -Link $user.DistinguishedName.ToUpperInvariant()))

            $result[0].IsOrphan | Should -Be $false
        }

        It 'does not treat an empty link as a match' {
            $result = @(Get-Krbtgt -User @(Get-UserFixture) -Computer @(
                    Get-ComputerFixture -Link ''))

            $result[0].IsOrphan | Should -Be $true
        }

        It 'tells orphans from linked accounts in the same domain' {
            $linked = Get-UserFixture -Sam 'krbtgt_1'
            $orphan = Get-UserFixture -Sam 'krbtgt_2'
            $result = @(Get-Krbtgt -User @($linked, $orphan) -Computer @(
                    Get-ComputerFixture -Name 'RODC1$' -Link $linked.DistinguishedName))

            ($result | Where-Object { $_.IsOrphan }).SamAccountName | Should -Be 'krbtgt_2'
            ($result | Where-Object { -not $_.IsOrphan }).SamAccountName | Should -Be 'krbtgt_1'
        }
    }

    Context 'result' {
        It 'returns the details of the account' {
            $user = Get-UserFixture -Sam 'krbtgt_7' -Name 'krbtgt_7'
            $result = @(Get-Krbtgt -User @($user) -Computer @())

            $result[0].Name | Should -Be 'krbtgt_7'
            $result[0].DistinguishedName | Should -Be 'CN=krbtgt_7,CN=Users,DC=contoso,DC=com'
            $result[0].Enabled | Should -Be $false
            $result[0].Created | Should -Be ([datetime]'2024-05-06')
            $result[0].PasswordLastSet | Should -Be ([datetime]'2024-05-07')
        }
    }
}
