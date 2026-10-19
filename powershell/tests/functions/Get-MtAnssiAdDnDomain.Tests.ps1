BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Get-MtAnssiAdDnDomain' {
    It 'returns the DNS name built from the DC components' {
        $domain = InModuleScope Maester {
            Get-MtAnssiAdDnDomain -DistinguishedName 'CN=Bob,OU=Staff,DC=north,DC=contoso,DC=com'
        }

        $domain | Should -Be 'north.contoso.com'
    }

    It 'ignores case in the DC keyword' {
        $domain = InModuleScope Maester {
            Get-MtAnssiAdDnDomain -DistinguishedName 'cn=Bob,dc=Contoso,Dc=Com'
        }

        $domain | Should -Be 'Contoso.Com'
    }

    It 'does not read a DC= that is part of an escaped value' {
        $domain = InModuleScope Maester {
            Get-MtAnssiAdDnDomain -DistinguishedName 'CN=Odd\,DC=fake,DC=real,DC=com'
        }

        $domain | Should -Be 'real.com'
    }

    It 'returns an empty string for an empty name' {
        $domain = InModuleScope Maester { Get-MtAnssiAdDnDomain -DistinguishedName '' }

        $domain | Should -Be ''
    }

    It 'returns an empty string when the name has no DC component' {
        $domain = InModuleScope Maester {
            Get-MtAnssiAdDnDomain -DistinguishedName 'CN=Configuration'
        }

        $domain | Should -Be ''
    }

    It 'drops the DomainDnsZones partition name from a DNS partition DN' {
        $domain = InModuleScope Maester {
            Get-MtAnssiAdDnDomain -DistinguishedName (
                'CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=com')
        }

        $domain | Should -Be 'corp.com'
    }

    It 'drops the ForestDnsZones partition name from a DNS partition DN' {
        $domain = InModuleScope Maester {
            Get-MtAnssiAdDnDomain -DistinguishedName 'DC=ForestDnsZones,DC=corp,DC=com'
        }

        $domain | Should -Be 'corp.com'
    }

    It 'ignores a DC component that belongs to an object name, not to the domain' {
        $domain = InModuleScope Maester {
            Get-MtAnssiAdDnDomain -DistinguishedName (
                'DC=zone.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=com')
        }

        $domain | Should -Be 'corp.com'
    }

    It 'keeps a domain whose first label is DomainDnsZones when it is the whole name' {
        $domain = InModuleScope Maester {
            Get-MtAnssiAdDnDomain -DistinguishedName 'CN=x,DC=DomainDnsZones'
        }

        $domain | Should -Be 'DomainDnsZones'
    }
}
