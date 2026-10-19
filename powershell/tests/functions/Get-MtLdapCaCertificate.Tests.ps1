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
            $attributes['cACertificate'] = $attribute
        }
        [PSCustomObject]@{ Attributes = $attributes }
    }

    function Invoke-Query {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection } {
                param($Connection)
                @(Get-MtLdapCaCertificate -Connection $Connection `
                    -SearchBase 'CN=Services,CN=Configuration,DC=x')
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Get-MtLdapCaCertificate' {
    It 'returns the name and the raw certificates of each object' {
        $script:values = @(, [byte[]](1, 2, 3)) + @(, [byte[]](4, 5))
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                DistinguishedName = ('CN=Root CA,CN=AIA,CN=Public Key' +
                    ' Services,CN=Services,CN=Configuration,DC=x')
                name = 'Root CA'
                DirectoryEntry    = Get-RawEntryFixture -Value $script:values
            }
            [PSCustomObject]@{
                DistinguishedName = ('CN=NTAuthCertificates,CN=Public Key' +
                    ' Services,CN=Services,CN=Configuration,DC=x')
                name = 'NTAuthCertificates'
                DirectoryEntry    = Get-RawEntryFixture -Value $null
            }
        }

        $result = Invoke-Query

        $result.Count | Should -Be 2
        $result[0].Name | Should -BeExactly 'Root CA'
        $result[0].DistinguishedName |
            Should -BeExactly ('CN=Root CA,CN=AIA,CN=Public Key' +
                ' Services,CN=Services,CN=Configuration,DC=x')
        @($result[0].Certificate).Count | Should -Be 2
        ($result[0].Certificate[1] -join ',') | Should -BeExactly '4,5'
        $result[0].Certificate[1] | Should -BeOfType [byte]
        @($result[1].Certificate).Count | Should -Be 0
    }

    It 'searches the subtree for objects with a certificate and asks for the raw values' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { }

        $null = Invoke-Query

        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            $SearchBase -eq 'CN=Services,CN=Configuration,DC=x' -and $Scope -eq 'Subtree' -and
            $Filter -eq '(cACertificate=*)' -and $Attributes -contains 'cACertificate' -and
            $Attributes -contains 'name' -and $ReturnDirectoryEntry.IsPresent
        }
    }

    It 'lets a failed search throw' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { throw 'LDAP search failed' }

        { Invoke-Query } | Should -Throw -ExpectedMessage 'LDAP search failed'
    }
}
