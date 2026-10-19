BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Invoke-Query {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection } {
                param($Connection)
                @(Get-MtLdapObjectOwner -Connection $Connection -SearchBase 'DC=x')
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Get-MtLdapObjectOwner' {
    It 'returns the name, class, creation date and owner of each object' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                DistinguishedName    = 'CN=alice,DC=x'
                name                 = 'alice'
                objectClass          = @('top', 'person', 'user')
                whenCreated          = [datetime]'2020-01-02'
                nTSecurityDescriptor = [PSCustomObject]@{
                    Owner = [PSCustomObject]@{ Sid = 'S-1-5-18' }
                }
            }
            [PSCustomObject]@{
                DistinguishedName = 'OU=x,DC=x'; name = 'x'; objectClass = 'organizationalUnit'
            }
        }

        $result = Invoke-Query

        $result.Count | Should -Be 2
        $result[0].DistinguishedName | Should -BeExactly 'CN=alice,DC=x'
        $result[0].Name | Should -BeExactly 'alice'
        $result[0].ObjectClass | Should -BeExactly 'user'
        $result[0].Created | Should -Be ([datetime]'2020-01-02')
        $result[0].OwnerSid | Should -BeExactly 'S-1-5-18'
        $result[1].ObjectClass | Should -BeExactly 'organizationalUnit'
        $null -eq $result[1].OwnerSid | Should -Be $true
    }

    It 'asks only for the owner of users, groups, organizational units and GPOs' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { }

        $null = Invoke-Query

        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            $SearchBase -eq 'DC=x' -and $Scope -eq 'Subtree' -and
            $Filter -eq ('(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)' +
                '(objectClass=groupPolicyContainer))') -and
            $Attributes -contains 'nTSecurityDescriptor' -and
            $Attributes -contains 'whenCreated' -and
            $Attributes -contains 'objectClass' -and $Attributes -contains 'name' -and
            [int]$SecurityDescriptorFlags -eq 1
        }
    }

    It 'lets a failed search throw' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { throw 'LDAP search failed' }

        { Invoke-Query } | Should -Throw -ExpectedMessage 'LDAP search failed'
    }
}
