BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Invoke-Query {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection } {
                param($Connection)
                @(Get-MtLdapDisplaySpecifier -Connection $Connection `
                        -ConfigurationNamingContext 'CN=Configuration,DC=x')
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Get-MtLdapDisplaySpecifier' {
    It 'returns the name and the context menus of each display specifier' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                DistinguishedName = 'CN=user-Display,CN=409,CN=DisplaySpecifiers,' +
                    'CN=Configuration,DC=x'
                name              = 'user-Display'
                adminContextMenu  = @('1,&Run,\\fs\x.vbs', '2,{0}')
                shellContextMenu  = '3,&Go,\\fs\y.cmd'
            }
            [PSCustomObject]@{ DistinguishedName = 'CN=group-Display,DC=x'; name = 'group-Display' }
        }

        $result = Invoke-Query

        $result.Count | Should -Be 2
        $result[0].Name | Should -BeExactly 'user-Display'
        $result[0].DistinguishedName | Should -Match '^CN=user-Display,CN=409,'
        $result[0].AdminContextMenu | Should -Be @('1,&Run,\\fs\x.vbs', '2,{0}')
        , $result[0].ShellContextMenu | Should -BeOfType [string[]]
        $result[0].ShellContextMenu | Should -Be @('3,&Go,\\fs\y.cmd')
        $result[1].AdminContextMenu.Count | Should -Be 0
        $result[1].ShellContextMenu.Count | Should -Be 0
    }

    It 'searches the DisplaySpecifiers container of the Configuration partition' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { }

        $null = Invoke-Query

        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            $SearchBase -eq 'CN=DisplaySpecifiers,CN=Configuration,DC=x' -and
            $Scope -eq 'Subtree' -and $Filter -eq '(objectClass=displaySpecifier)' -and
            $Attributes -contains 'adminContextMenu' -and
            $Attributes -contains 'shellContextMenu' -and $Attributes -contains 'name'
        }
    }

    It 'lets a failed search throw' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { throw 'LDAP search failed' }

        { Invoke-Query } | Should -Throw -ExpectedMessage 'LDAP search failed'
    }
}
