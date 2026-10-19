BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'ConvertTo-MtAnssiAdMarkdownTable' {
    It 'builds the header, the separator and one row per finding in column order' {
        $table = InModuleScope Maester {
            $items = @(
                [PSCustomObject]@{ Name = 'a'; Value = 1 }
                [PSCustomObject]@{ Name = 'b'; Value = 2 }
            )
            ConvertTo-MtAnssiAdMarkdownTable -DefaultDomain 'd.test' -InputObject $items `
                -Column ([ordered]@{ 'Name' = { $_.Name }; 'Value' = { $_.Value } })
        }

        $table | Should -Be (
            "| Domain | Name | Value |`n| --- | --- | --- |`n" +
            "| d.test | a | 1 |`n| d.test | b | 2 |`n")
    }

    It 'escapes markdown and pipes in cells and headers' {
        $table = InModuleScope Maester {
            $items = @([PSCustomObject]@{ Name = '[click](https://evil.example)|x' })
            ConvertTo-MtAnssiAdMarkdownTable -DefaultDomain 'd.test' -InputObject $items `
                -Column ([ordered]@{ 'Na|me' = { $_.Name } })
        }

        $table | Should -Be (
            "| Domain | Na\|me |`n| --- | --- |`n" +
            "| d.test | \[click\]\(https://evil.example\)\|x |`n")
    }

    It 'keeps a row on one line when a value contains line breaks' {
        $table = InModuleScope Maester {
            $items = @([PSCustomObject]@{ Name = "first`nsecond" })
            ConvertTo-MtAnssiAdMarkdownTable -DefaultDomain 'd.test' -InputObject $items `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
        }

        $table | Should -Be "| Domain | Name |`n| --- | --- |`n| d.test | first second |`n"
    }

    It 'joins several values of a cell with a comma' {
        $table = InModuleScope Maester {
            $items = @([PSCustomObject]@{ Tags = @('x', 'y', 'z') })
            ConvertTo-MtAnssiAdMarkdownTable -DefaultDomain 'd.test' -InputObject $items `
                -Column ([ordered]@{ 'Tags' = { $_.Tags } })
        }

        $table | Should -Be "| Domain | Tags |`n| --- | --- |`n| d.test | x, y, z |`n"
    }

    It 'leaves the cell empty for a null value' {
        $table = InModuleScope Maester {
            $items = @([PSCustomObject]@{ Name = $null })
            ConvertTo-MtAnssiAdMarkdownTable -DefaultDomain 'd.test' -InputObject $items `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
        }

        $table | Should -Be "| Domain | Name |`n| --- | --- |`n| d.test |  |`n"
    }

    It 'returns only the header for no findings' {
        $table = InModuleScope Maester {
            ConvertTo-MtAnssiAdMarkdownTable -DefaultDomain 'd.test' -InputObject @() `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
        }

        $table | Should -Be "| Domain | Name |`n| --- | --- |`n"
    }

    It 'caps the rows and says how many are shown' {
        $table = InModuleScope Maester {
            $items = 1..5 | ForEach-Object { [PSCustomObject]@{ Name = "n$_" } }
            ConvertTo-MtAnssiAdMarkdownTable -DefaultDomain 'd.test' -InputObject $items -MaxRow 2 `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
        }

        $table | Should -Be (
            "| Domain | Name |`n| --- | --- |`n| d.test | n1 |`n| d.test | n2 |`n" +
            "`nShowing the first 2 of 5.`n")
    }

    It 'does not add the cap line when the findings fit exactly' {
        $table = InModuleScope Maester {
            $items = 1..2 | ForEach-Object { [PSCustomObject]@{ Name = "n$_" } }
            ConvertTo-MtAnssiAdMarkdownTable -DefaultDomain 'd.test' -InputObject $items -MaxRow 2 `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
        }

        $table | Should -Be (
            "| Domain | Name |`n| --- | --- |`n| d.test | n1 |`n| d.test | n2 |`n")
    }
}

Describe 'ConvertTo-MtAnssiAdMarkdownTable Domain column' {
    It 'puts a Domain column first and reads it from each row DN' {
        $table = InModuleScope Maester {
            $items = @(
                [PSCustomObject]@{ Name = 'a'; DistinguishedName = 'CN=a,DC=north,DC=corp,DC=com' }
                [PSCustomObject]@{ Name = 'b'; DistinguishedName = 'CN=b,DC=corp,DC=com' }
            )
            ConvertTo-MtAnssiAdMarkdownTable -InputObject $items `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
        }

        $table | Should -Be (
            "| Domain | Name |`n| --- | --- |`n| north.corp.com | a |`n| corp.com | b |`n")
    }

    It 'uses the scanned domain for a row without a DN' {
        $table = InModuleScope Maester {
            Mock Get-MtAnssiAdScannedDomain { 'scan.example' }
            $items = @([PSCustomObject]@{ Name = 'a' })
            ConvertTo-MtAnssiAdMarkdownTable -InputObject $items `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
        }

        $table | Should -Be "| Domain | Name |`n| --- | --- |`n| scan.example | a |`n"
    }

    It 'prefers an explicit DefaultDomain over the scanned domain' {
        $table = InModuleScope Maester {
            Mock Get-MtAnssiAdScannedDomain { 'scan.example' }
            $items = @([PSCustomObject]@{ Name = 'a' })
            ConvertTo-MtAnssiAdMarkdownTable -InputObject $items -DefaultDomain 'given.example' `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
        }

        $table | Should -Be "| Domain | Name |`n| --- | --- |`n| given.example | a |`n"
    }

    It 'shows a dash when no domain can be found' {
        $table = InModuleScope Maester {
            Mock Get-MtAnssiAdScannedDomain { $null }
            $items = @([PSCustomObject]@{ Name = 'a' })
            ConvertTo-MtAnssiAdMarkdownTable -InputObject $items `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
        }

        $table | Should -Be "| Domain | Name |`n| --- | --- |`n| - | a |`n"
    }

    It 'does not look up the scanned domain when every row has a DN' {
        InModuleScope Maester {
            Mock Get-MtAnssiAdScannedDomain { 'scan.example' }
            $items = @([PSCustomObject]@{ Name = 'a'; DistinguishedName = 'CN=a,DC=x,DC=y' })
            $null = ConvertTo-MtAnssiAdMarkdownTable -InputObject $items `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
            Should -Invoke Get-MtAnssiAdScannedDomain -Times 0 -Exactly
        }
    }

    It 'reads the DN through DomainSource when the finding wraps the object' {
        $table = InModuleScope Maester {
            Mock Get-MtAnssiAdScannedDomain { 'scan.example' }
            $items = @(
                [PSCustomObject]@{
                    Item = [PSCustomObject]@{ DistinguishedName = 'CN=a,DC=child,DC=corp' }
                }
            )
            ConvertTo-MtAnssiAdMarkdownTable -InputObject $items `
                -DomainSource { $_.Item.DistinguishedName } `
                -Column ([ordered]@{ 'Name' = { $_.Item.DistinguishedName } })
        }

        $table | Should -Match '\| child\.corp \|'
    }

    It 'looks up the scanned domain once for several rows without a DN' {
        InModuleScope Maester {
            Mock Get-MtAnssiAdScannedDomain { 'scan.example' }
            $items = 1..3 | ForEach-Object { [PSCustomObject]@{ Name = "n$_" } }
            $null = ConvertTo-MtAnssiAdMarkdownTable -InputObject $items `
                -Column ([ordered]@{ 'Name' = { $_.Name } })
            Should -Invoke Get-MtAnssiAdScannedDomain -Times 1 -Exactly
        }
    }
}

Describe 'Get-MtAnssiAdScannedDomain' {
    It 'returns the DNS root of the collected domain' {
        $domain = InModuleScope Maester {
            Mock Get-MtADDomainState {
                [PSCustomObject]@{ Domain = [PSCustomObject]@{ DnsRoot = 'a.b' } }
            }
            Get-MtAnssiAdScannedDomain
        }

        $domain | Should -Be 'a.b'
    }

    It 'returns null when the state cannot be read' {
        $domain = InModuleScope Maester {
            Mock Get-MtADDomainState { throw 'no connection' }
            Get-MtAnssiAdScannedDomain
        }

        $domain | Should -BeNullOrEmpty
    }

    It 'reads only the Domain category to find the scanned domain' {
        InModuleScope Maester {
            Mock Get-MtADDomainState {
                [PSCustomObject]@{ Domain = [PSCustomObject]@{ DnsRoot = 'a.b' } }
            }
            $null = Get-MtAnssiAdScannedDomain
            Should -Invoke Get-MtADDomainState -Times 1 -Exactly -ParameterFilter {
                @($Categories) -join ',' -eq 'Domain'
            }
        }
    }
}
