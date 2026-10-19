BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Entry {
        param([string] $Name, [string] $Kind = 'User')
        @{
            Kind = $Kind
            Item = [PSCustomObject]@{
                Name              = $Name
                DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            }
        }
    }

    function Get-Hit {
        param([hashtable] $Entry, [string] $Group, [string] $Link = 'Member')
        [PSCustomObject]@{ Entry = $Entry; Group = $Group; Link = $Link }
    }

    function Get-Account {
        param([object[]] $Hit)
        InModuleScope Maester -Parameters @{ Hit = $Hit } {
            param($Hit)
            @(ConvertTo-MtAnssiAdPrivilegedAccount -Hit $Hit)
        }
    }
}

Describe 'ConvertTo-MtAnssiAdPrivilegedAccount' {
    It 'returns one account per path with its name, kind and collected item' {
        $alice = Get-Entry -Name 'alice'
        $pc = Get-Entry -Name 'PC1' -Kind 'Computer'

        $accounts = Get-Account -Hit @(
            Get-Hit -Entry $alice -Group 'Domain Admins'
            Get-Hit -Entry $pc -Group 'Domain Admins'
        )

        $accounts.Count | Should -Be 2
        $found = @($accounts | Where-Object { $_.Kind -eq 'Computer' })[0]
        $found.DistinguishedName | Should -BeExactly 'CN=PC1,DC=contoso,DC=com'
        $found.Item.Name | Should -BeExactly 'PC1'
        @($found.Group) | Should -Be @('Domain Admins')
        @($found.Link) | Should -Be @('Member')
    }

    It 'merges the paths of one account into sorted, distinct groups and links' {
        $alice = Get-Entry -Name 'alice'

        $accounts = Get-Account -Hit @(
            Get-Hit -Entry $alice -Group 'Domain Admins' -Link 'PrimaryGroup'
            Get-Hit -Entry $alice -Group 'Administrators'
            Get-Hit -Entry $alice -Group 'Domain Admins'
            Get-Hit -Entry $alice -Group 'Administrators'
        )

        $accounts.Count | Should -Be 1
        @($accounts[0].Group) | Should -Be @('Administrators', 'Domain Admins')
        @($accounts[0].Link) | Should -Be @('Member', 'PrimaryGroup')
    }

    It 'keeps accounts with the same name in different places apart' {
        $first = Get-Entry -Name 'alice'
        $second = @{
            Kind = 'User'
            Item = [PSCustomObject]@{
                Name              = 'alice'
                DistinguishedName = 'CN=alice,OU=Other,DC=contoso,DC=com'
            }
        }

        $accounts = Get-Account -Hit @(
            Get-Hit -Entry $first -Group 'Domain Admins'
            Get-Hit -Entry $second -Group 'Domain Admins'
        )

        $accounts.Count | Should -Be 2
    }

    It 'returns nothing for no path' {
        (Get-Account -Hit @()).Count | Should -Be 0
    }
}
