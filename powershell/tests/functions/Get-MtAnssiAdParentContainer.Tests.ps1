BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Parent {
        param([string[]] $Name, [string] $DomainDn = 'DC=contoso,DC=com')
        InModuleScope Maester -Parameters @{ Name = $Name; DomainDn = $DomainDn } {
            param($Name, $DomainDn)
            @(Get-MtAnssiAdParentContainer -DistinguishedName $Name -DomainDn $DomainDn)
        }
    }
}

Describe 'Get-MtAnssiAdParentContainer' {
    It 'returns the containers above an object, nearest first, without the domain root' {
        $result = Get-Parent -Name @('CN=alice,OU=Admins,OU=Tier0,DC=contoso,DC=com')

        $result -join ';' |
            Should -BeExactly 'OU=Admins,OU=Tier0,DC=contoso,DC=com;OU=Tier0,DC=contoso,DC=com'
    }

    It 'returns each container once across objects, in the order first met, whatever the case' {
        $result = Get-Parent -Name @(
            'CN=a,OU=Admins,DC=contoso,DC=com'
            'CN=b,CN=Users,DC=contoso,DC=com'
            'CN=c,ou=admins,DC=contoso,DC=com'
        )

        $result -join ';' |
            Should -BeExactly 'OU=Admins,DC=contoso,DC=com;CN=Users,DC=contoso,DC=com'
    }

    It 'keeps commas escaped in a name' {
        $result = Get-Parent -Name @('CN=Doe\, John,OU=Sales\, East,DC=contoso,DC=com')

        $result -join ';' | Should -BeExactly 'OU=Sales\, East,DC=contoso,DC=com'
    }

    It 'returns nothing for an object right below the root or outside the domain' {
        @(Get-Parent -Name @('CN=x,DC=contoso,DC=com', 'CN=y,OU=z,DC=other,DC=com')).Count |
            Should -Be 0
    }

    It 'matches the domain root without regard to case' {
        (Get-Parent -Name @('CN=a,OU=b,dc=CONTOSO,dc=com')) -join ';' |
            Should -BeExactly 'OU=b,dc=CONTOSO,dc=com'
    }
}
