BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:psoDn = 'CN=Admins,CN=Password Settings Container,CN=System,DC=contoso,DC=com'

    function Use-Ldap {
        param([AllowNull()] [object] $Entry)
        $result = $Entry
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith ({ $result }.GetNewClosure())
    }

    function Read-Setting {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection; Dn = $script:psoDn } {
                param($Connection, $Dn)
                Read-MtAnssiAdPasswordSetting -Connection $Connection -DistinguishedName $Dn
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Read-MtAnssiAdPasswordSetting' {
    It 'returns the name, minimum length and maximum age of the policy' {
        Use-Ldap -Entry ([PSCustomObject]@{
                name                         = 'Admins'
                'msDS-MinimumPasswordLength' = 15
                'msDS-MaximumPasswordAge'    = [timespan]::FromDays(365)
            })

        $setting = Read-Setting

        $setting.Source | Should -BeExactly 'Fine-grained policy Admins'
        $setting.MinLength | Should -Be 15
        $setting.MaxAge | Should -Be ([timespan]::FromDays(365))
    }

    It 'reads the policy object with a base search' {
        Use-Ldap -Entry ([PSCustomObject]@{ name = 'Admins'; 'msDS-MinimumPasswordLength' = 15 })

        $null = Read-Setting

        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            $SearchBase -eq $script:psoDn -and $Scope -eq 'Base' -and $PageSize -eq 0 -and
            $Attributes -contains 'msDS-MinimumPasswordLength' -and
            $Attributes -contains 'msDS-MaximumPasswordAge' -and $Attributes -contains 'name'
        }
    }

    It 'throws when <Case>' -ForEach @(
        @{ Case = 'the minimum length is missing'; Entry = [PSCustomObject]@{ name = 'Admins' } }
        @{ Case = 'the object is not returned'; Entry = $null }
    ) {
        Use-Ldap -Entry $Entry

        { Read-Setting } | Should -Throw -ExpectedMessage "*'$psoDn' could not be read*"
    }
}
