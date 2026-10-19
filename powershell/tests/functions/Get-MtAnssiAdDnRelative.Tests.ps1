BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Get-MtAnssiAdDnRelative' {
    It 'removes the domain suffix from a distinguished name' {
        $dn = InModuleScope Maester {
            Get-MtAnssiAdDnRelative -DistinguishedName 'CN=Users,DC=north,DC=corp,DC=com'
        }

        $dn | Should -Be 'CN=Users'
    }

    It 'keeps the parent containers' {
        $dn = InModuleScope Maester {
            Get-MtAnssiAdDnRelative -DistinguishedName 'CN=MicrosoftDNS,CN=System,DC=corp,DC=com'
        }

        $dn | Should -Be 'CN=MicrosoftDNS,CN=System'
    }

    It 'keeps the DNS partition name that distinguishes the container' {
        $dn = InModuleScope Maester {
            Get-MtAnssiAdDnRelative -DistinguishedName (
                'CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=com')
        }

        $dn | Should -Be 'CN=MicrosoftDNS,DC=DomainDnsZones'
    }

    It 'ignores the case of the suffix' {
        $dn = InModuleScope Maester {
            Get-MtAnssiAdDnRelative -DistinguishedName 'cn=Users,dc=Corp,Dc=Com'
        }

        $dn | Should -Be 'cn=Users'
    }

    It 'keeps the whole name when it is the domain itself' {
        $dn = InModuleScope Maester {
            Get-MtAnssiAdDnRelative -DistinguishedName 'DC=corp,DC=com'
        }

        $dn | Should -Be 'DC=corp,DC=com'
    }

    It 'keeps a name that has no DC components' {
        $dn = InModuleScope Maester { Get-MtAnssiAdDnRelative -DistinguishedName 'Domain Admins' }

        $dn | Should -Be 'Domain Admins'
    }

    It 'returns an empty string for an empty name' {
        $dn = InModuleScope Maester { Get-MtAnssiAdDnRelative -DistinguishedName '' }

        $dn | Should -Be ''
    }
}
