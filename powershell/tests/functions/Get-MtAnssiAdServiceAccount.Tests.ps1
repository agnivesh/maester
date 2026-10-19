BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-UserFixture {
        param(
            [string] $Name = 'svc',
            [AllowNull()] [object] $Types = 28,
            [AllowNull()] [object] $Spn = @('HTTP/app.contoso.com'),
            [object] $Enabled = $true
        )
        [PSCustomObject]@{
            DistinguishedName        = "CN=$Name,OU=Service,DC=contoso,DC=com"
            Name                     = $Name
            Enabled                  = $Enabled
            ServicePrincipalName     = $Spn
            SupportedEncryptionTypes = $Types
            LastLogonDate            = [datetime]'2026-01-02'
        }
    }

    function Get-Account {
        param([AllowNull()] [object[]] $User)
        InModuleScope Maester -Parameters @{ User = $User } {
            param($User)
            Get-MtAnssiAdServiceAccount -User $User
        }
    }
}

Describe 'Get-MtAnssiAdServiceAccount' {
    Context 'which accounts are returned' {
        It 'returns an enabled account that has a service principal name' {
            $result = @(Get-Account -User @(Get-UserFixture -Name 'svc'))

            $result.Count | Should -Be 1
            $result[0].Name | Should -Be 'svc'
            $result[0].DistinguishedName | Should -Be 'CN=svc,OU=Service,DC=contoso,DC=com'
        }

        It 'skips a disabled account' {
            @(Get-Account -User @(Get-UserFixture -Enabled $false)).Count | Should -Be 0
        }

        It 'skips an account whose enabled state is unknown' {
            @(Get-Account -User @(Get-UserFixture -Enabled $null)).Count | Should -Be 0
        }

        It 'skips an account without a service principal name' -ForEach @(
            @{ Spn = $null }
            @{ Spn = @() }
            @{ Spn = @($null) }
            @{ Spn = '' }
            @{ Spn = @('') }
        ) {
            @(Get-Account -User @(Get-UserFixture -Spn $Spn)).Count | Should -Be 0
        }

        It 'returns nothing for null or empty input' {
            @(Get-Account -User $null).Count | Should -Be 0
            @(Get-Account -User @()).Count | Should -Be 0
        }

        It 'returns every matching account' {
            $result = @(Get-Account -User @(
                    (Get-UserFixture -Name 'a')
                    (Get-UserFixture -Name 'off' -Enabled $false)
                    (Get-UserFixture -Name 'b')
                ))

            ($result | ForEach-Object { $_.Name }) -join ',' | Should -Be 'a,b'
        }
    }

    Context 'service principal name' {
        It 'returns the first name of several' {
            $result = @(Get-Account -User @(Get-UserFixture -Spn @('MSSQL/db1', 'MSSQL/db2')))

            $result[0].ServicePrincipalName | Should -Be 'MSSQL/db1'
        }

        It 'returns a single name given as text' {
            $result = @(Get-Account -User @(Get-UserFixture -Spn 'HTTP/app'))

            $result[0].ServicePrincipalName | Should -Be 'HTTP/app'
        }

        It 'skips an empty first value and returns the first real name' {
            $result = @(Get-Account -User @(Get-UserFixture -Spn @('', 'HTTP/app')))

            $result[0].ServicePrincipalName | Should -Be 'HTTP/app'
        }
    }

    Context 'AES support' {
        It 'declares AES for <Types>' -ForEach @(
            @{ Types = 8 }
            @{ Types = 16 }
            @{ Types = 24 }
            @{ Types = 28 }
            @{ Types = 56 }
        ) {
            @(Get-Account -User @(Get-UserFixture -Types $Types))[0].SupportsAes | Should -Be $true
        }

        It 'does not declare AES for <Types>' -ForEach @(
            @{ Types = $null }
            @{ Types = 0 }
            @{ Types = 1 }
            @{ Types = 4 }
            @{ Types = 7 }
            @{ Types = 32 }
            @{ Types = 36 }
        ) {
            @(Get-Account -User @(Get-UserFixture -Types $Types))[0].SupportsAes | Should -Be $false
        }

        It 'returns the value and the last logon unchanged' {
            $account = @(Get-Account -User @(Get-UserFixture -Types 4))[0]

            $account.SupportedEncryptionTypes | Should -Be 4
            $account.LastLogonDate | Should -Be ([datetime]'2026-01-02')
        }
    }
}
