BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:existingAttribute = @(
        'distinguishedName', 'name', 'sAMAccountName', 'groupType', 'adminCount', 'whenCreated',
        'whenChanged', 'managedBy', 'objectSid', 'sIDHistory', 'isCriticalSystemObject'
    )

    $script:existingProperty = @(
        'DistinguishedName', 'Name', 'SamAccountName', 'GroupCategory', 'GroupScope', 'AdminCount',
        'Created', 'Modified', 'ManagedBy', 'Sid', 'SidHistory', 'IsCriticalSystemObject'
    )

    function Use-GroupEntry {
        param([hashtable] $Extra = @{})
        $entry = [ordered]@{
            DistinguishedName      = 'CN=Tier0,OU=Groups,DC=contoso,DC=com'
            name                   = 'Tier0'
            sAMAccountName         = 'Tier0'
            groupType              = -2147483646
            adminCount             = 1
            objectSid              = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1200' }
            isCriticalSystemObject = $false
        }
        foreach ($key in $Extra.Keys) { $entry[$key] = $Extra[$key] }
        $groupEntry = [PSCustomObject]$entry
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith ({ $groupEntry }.GetNewClosure())
    }

    function Invoke-Collector {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection } {
                param($Connection)
                Get-MtLdapGroup -Connection $Connection -SearchBase 'DC=contoso,DC=com'
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Get-MtLdapGroup' {
    Context 'existing output' {
        It 'keeps every property it returned before, in the same order' {
            Use-GroupEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            ($names | Select-Object -First $existingProperty.Count) -join ',' |
                Should -Be ($existingProperty -join ',')
        }

        It 'keeps requesting every attribute it requested before' {
            Use-GroupEntry

            $null = Invoke-Collector

            foreach ($attribute in $existingAttribute) {
                $expected = [scriptblock]::Create("`$Attributes -contains '$attribute'")
                Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -ParameterFilter $expected
            }
        }

        It 'keeps searching group objects under the search base' {
            Use-GroupEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $Filter -eq '(objectClass=group)' -and $SearchBase -eq 'DC=contoso,DC=com' -and
                $Scope -eq 'Subtree'
            }
        }

        It 'keeps the values of the properties other tests read' {
            Use-GroupEntry

            $group = Invoke-Collector

            $group.DistinguishedName | Should -BeExactly 'CN=Tier0,OU=Groups,DC=contoso,DC=com'
            $group.Name | Should -BeExactly 'Tier0'
            $group.Sid.Value | Should -BeExactly 'S-1-5-21-1-2-3-1200'
            $group.GroupCategory | Should -BeExactly 'Security'
            $group.GroupScope | Should -BeExactly 'Global'
            $group.AdminCount | Should -Be 1
        }

        It 'keeps reading <Scope> <Category> groups from groupType <Type>' -ForEach @(
            @{ Type = 4; Scope = 'DomainLocal'; Category = 'Distribution' }
            @{ Type = -2147483640; Scope = 'Universal'; Category = 'Security' }
            @{ Type = 0; Scope = 'Unknown'; Category = 'Distribution' }
        ) {
            Use-GroupEntry -Extra @{ groupType = $Type }

            $group = Invoke-Collector

            $group.GroupScope | Should -BeExactly $Scope
            $group.GroupCategory | Should -BeExactly $Category
        }

        It 'keeps returning nothing when the search fails' {
            Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { throw 'LDAP search failed' }

            @(Invoke-Collector).Count | Should -Be 0
        }
    }

    Context 'parent groups' {
        It 'requests the memberOf attribute' {
            Use-GroupEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Attributes -contains 'memberOf' }
        }

        It 'returns the parent groups' {
            $parents = @('CN=A,DC=contoso,DC=com', 'CN=B,DC=contoso,DC=com')
            Use-GroupEntry -Extra @{ memberOf = $parents }

            @((Invoke-Collector).MemberOf) | Should -Be $parents
        }

        It 'returns a single parent group as a list' {
            Use-GroupEntry -Extra @{ memberOf = 'CN=A,DC=contoso,DC=com' }

            $memberOf = (Invoke-Collector).MemberOf

            , $memberOf | Should -BeOfType [string[]]
            $memberOf.Count | Should -Be 1
        }

        It 'returns an empty list for a group without a parent' {
            Use-GroupEntry -Extra @{ memberOf = $null }

            $memberOf = (Invoke-Collector).MemberOf

            $null -ne $memberOf | Should -Be $true
            $memberOf.Count | Should -Be 0
        }

        It 'returns $null when the server sent only a range of the parent groups' {
            Use-GroupEntry -Extra @{
                memberOf                  = $null
                'memberOf;range=0-1499'   = @('CN=A,DC=contoso,DC=com')
            }

            $null -eq (Invoke-Collector).MemberOf | Should -Be $true
        }

        It 'adds the property after the existing ones' {
            Use-GroupEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names[-1] | Should -BeExactly 'MemberOf'
        }
    }
}
