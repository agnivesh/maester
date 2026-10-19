BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Get-MtAnssiAdDomainIsForestRoot' {
    It '<Name>' -ForEach @(
        @{ Name = 'is true when the domain is the forest root'
            Domain = [PSCustomObject]@{ DnsRoot = 'corp.com'; Forest = 'corp.com' }
            Expected = $true }
        @{ Name = 'is false for a child domain'
            Domain = [PSCustomObject]@{ DnsRoot = 'north.corp.com'; Forest = 'corp.com' }
            Expected = $false }
        @{ Name = 'ignores the case of the names'
            Domain = [PSCustomObject]@{ DnsRoot = 'CORP.com'; Forest = 'corp.COM' }
            Expected = $true }
        @{ Name = 'is false when the DNS root is empty'
            Domain = [PSCustomObject]@{ DnsRoot = ''; Forest = '' }; Expected = $false }
        @{ Name = 'is false when the forest is unknown'
            Domain = [PSCustomObject]@{ DnsRoot = 'corp.com'; Forest = $null }; Expected = $false }
        @{ Name = 'is false when there is no domain'; Domain = $null; Expected = $false }
    ) {
        $result = InModuleScope Maester -Parameters @{ Domain = $Domain } {
            param($Domain)
            Get-MtAnssiAdDomainIsForestRoot -Domain $Domain
        }

        $result | Should -Be $Expected
    }
}
