BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-RawEntryFixture {
        param([object[]] $Value)
        $attributes = @{}
        if ($null -ne $Value) {
            $attribute = [PSCustomObject]@{ Value = $Value }
            $attribute | Add-Member -MemberType ScriptMethod -Name GetValues -Value {
                param($Type)
                $null = $Type
                , @($this.Value)
            }
            $attributes['dNSProperty'] = $attribute
        }
        [PSCustomObject]@{ Attributes = $attributes }
    }

    function Invoke-Query {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection } {
                param($Connection)
                @(Get-MtLdapDnsZone -Connection $Connection -SearchBase 'DC=DomainDnsZones,DC=x')
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Get-MtLdapDnsZone' {
    It 'returns the name and the raw property values of each zone' {
        $script:values = @(, [byte[]](1, 2, 3)) + @(, [byte[]](4, 5))
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                DistinguishedName = 'DC=a.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=x'
                name = 'a.com'
                DirectoryEntry    = Get-RawEntryFixture -Value $script:values
            }
            [PSCustomObject]@{
                DistinguishedName = 'DC=b.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=x'
                name = 'b.com'
                DirectoryEntry    = Get-RawEntryFixture -Value $null
            }
        }

        $result = Invoke-Query

        $result.Count | Should -Be 2
        $result[0].Name | Should -BeExactly 'a.com'
        $result[0].DistinguishedName |
            Should -BeExactly 'DC=a.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=x'
        @($result[0].Property).Count | Should -Be 2
        ($result[0].Property[1] -join ',') | Should -BeExactly '4,5'
        @($result[1].Property).Count | Should -Be 0
    }

    It 'searches the subtree for dnsZone objects with their properties and raw values' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { }

        $null = Invoke-Query

        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            $SearchBase -eq 'DC=DomainDnsZones,DC=x' -and $Scope -eq 'Subtree' -and
            $Filter -eq '(objectClass=dnsZone)' -and $Attributes -contains 'dNSProperty' -and
            $Attributes -contains 'name' -and $ReturnDirectoryEntry.IsPresent
        }
    }

    It 'lets a failed search throw' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { throw 'LDAP search failed' }

        { Invoke-Query } | Should -Throw -ExpectedMessage 'LDAP search failed'
    }
}
