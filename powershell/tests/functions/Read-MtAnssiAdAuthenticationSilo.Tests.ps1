BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:siloDn = 'CN=Tier0,CN=AuthN Silos,CN=AuthN Policy Configuration,' +
        'CN=Services,CN=Configuration,DC=x'

    function Use-Ldap {
        param([AllowNull()] [object] $Entry, [string[]] $Member = @())
        $result = $Entry
        $members = $Member
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith ({ $result }.GetNewClosure())
        Mock Get-MtLdapRangedValue -ModuleName Maester -MockWith ({ $members }.GetNewClosure())
    }

    function Read-Silo {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection; Dn = $script:siloDn } {
                param($Connection, $Dn)
                Read-MtAnssiAdAuthenticationSilo -Connection $Connection -DistinguishedName $Dn
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Read-MtAnssiAdAuthenticationSilo' {
    It 'returns the name, the enforced state and the members of the silo' {
        $entry = [PSCustomObject]@{ name = 'Tier0'; 'msDS-AuthNPolicySiloEnforced' = 'TRUE' }
        Use-Ldap -Entry $entry -Member 'CN=alice,DC=x', 'CN=bob,DC=x'

        $silo = Read-Silo

        $silo.Name | Should -BeExactly 'Tier0'
        $silo.Enforced | Should -Be $true
        $silo.Member.Count | Should -Be 2
        $silo.Member.Contains('cn=ALICE,dc=x') | Should -Be $true
    }

    It 'treats <Value> as not enforced' -ForEach @(
        @{ Value = 'FALSE' }
        @{ Value = $null }
    ) {
        $entry = [PSCustomObject]@{ name = 'Tier0'; 'msDS-AuthNPolicySiloEnforced' = $Value }
        Use-Ldap -Entry $entry

        (Read-Silo).Enforced | Should -Be $false
    }

    It 'reads the silo with a base search and its members with ranged reads' {
        Use-Ldap -Entry ([PSCustomObject]@{ name = 'Tier0' })

        $null = Read-Silo

        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $SearchBase -eq $script:siloDn -and $Scope -eq 'Base' -and $PageSize -eq 0 -and
            $Attributes -contains 'msDS-AuthNPolicySiloEnforced' -and $Attributes -contains 'name'
        }
        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $DistinguishedName -eq $script:siloDn -and
            $AttributeName -eq 'msDS-AuthNPolicySiloMembers'
        }
    }

    It 'throws when the silo is not returned' {
        Use-Ldap -Entry $null

        { Read-Silo } | Should -Throw -ExpectedMessage '*could not be read*'
    }
}
