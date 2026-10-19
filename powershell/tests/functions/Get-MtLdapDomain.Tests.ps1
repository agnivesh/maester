BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:existingAttribute = @(
        'distinguishedName', 'name', 'objectSid', 'lockoutDuration', 'lockoutThreshold',
        'maxPwdAge',
        'minPwdAge', 'minPwdLength', 'ms-DS-MachineAccountQuota', 'pwdProperties',
        'pwdHistoryLength', 'rIDAvailablePool', 'objectVersion', 'whenCreated', 'whenChanged',
        'msDS-Behavior-Version', 'fSMORoleOwner', 'msDS-AllowedDNSSuffixes',
        'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'
    )

    $script:existingProperty = @(
        'DistinguishedName', 'Name', 'ObjectSid', 'DomainSID', 'LockoutDuration',
        'LockoutThreshold', 'MaxPwdAge', 'MinPwdAge', 'MinPwdLength', 'MsDsMachineAccountQuota',
        'PwdProperties', 'PwdHistoryLength', 'RIDAvailablePool', 'ObjectVersion', 'WhenCreated',
        'WhenChanged', 'DnsRoot', 'Forest', 'DomainMode', 'InfrastructureMaster', 'PDCEmulator',
        'RIDMaster', 'NetBIOSName', 'AllowedDnsSuffixes', 'ExpirePasswordsOnSmartCardOnlyAccounts',
        'DomainUpdateRevision'
    )

    $script:partitionsDn = 'CN=Partitions,CN=Configuration,DC=contoso,DC=com'

    function Get-CrossRef {
        param([string] $NcName, [string] $NetBios, [AllowNull()] [object] $SystemFlags)
        [PSCustomObject]@{ nCName = $NcName; nETBIOSName = $NetBios; systemFlags = $SystemFlags }
    }

    function Use-CrossRef {
        param([object[]] $CrossRef)
        $crossRefs = $CrossRef
        Mock Invoke-MtLdapSearch -ModuleName Maester -ParameterFilter {
            $Filter -eq '(objectClass=crossRef)'
        } -MockWith ({ $crossRefs }.GetNewClosure())
    }

    $script:updateDn = 'CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,DC=contoso,DC=com'

    function Use-DomainUpdate {
        param([AllowNull()] [object] $Revision = '16', [switch] $Missing, [switch] $Fail)
        $update = [PSCustomObject]@{ DistinguishedName = $script:updateDn; revision = $Revision }
        $filter = {
            $SearchBase -eq 'CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,DC=contoso,DC=com'
        }
        if ($Fail) {
            Mock Invoke-MtLdapSearch -ModuleName Maester -ParameterFilter $filter -MockWith {
                throw 'LDAP search failed. No such object'
            }
        } elseif ($Missing) {
            Mock Invoke-MtLdapSearch -ModuleName Maester -ParameterFilter $filter `
                -MockWith { $null }
        } else {
            Mock Invoke-MtLdapSearch -ModuleName Maester -ParameterFilter $filter `
                -MockWith ({ $update }.GetNewClosure())
        }
    }

    function Use-DomainEntry {
        param([hashtable] $Extra = @{})
        $entry = [ordered]@{
            DistinguishedName          = 'DC=contoso,DC=com'
            name                       = 'contoso'
            objectSid                  = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3' }
            lockoutThreshold           = 5
            minPwdLength               = 14
            'ms-DS-MachineAccountQuota' = 0
            pwdProperties              = 1
            'msDS-Behavior-Version'    = 7
        }
        foreach ($key in $Extra.Keys) { $entry[$key] = $Extra[$key] }
        $domainEntry = [PSCustomObject]$entry

        Mock Get-MtLdapRootDse -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                DefaultNamingContext      = 'DC=contoso,DC=com'
                ConfigurationNamingContext = 'CN=Configuration,DC=contoso,DC=com'
                RootDomainNamingContext   = 'DC=contoso,DC=com'
            }
        }
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { $null }
        Mock Invoke-MtLdapSearch -ModuleName Maester -ParameterFilter {
            $Filter -eq '(objectClass=domainDNS)'
        } -MockWith ({ $domainEntry }.GetNewClosure())
    }

    function Invoke-Collector {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection } {
                param($Connection)
                Get-MtLdapDomain -Connection $Connection
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Get-MtLdapDomain' {
    Context 'existing output' {
        It 'keeps every property it returned before, in the same order' {
            Use-DomainEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            ($names | Select-Object -First $existingProperty.Count) -join ',' |
                Should -Be ($existingProperty -join ',')
        }

        It 'keeps requesting every attribute it requested before' {
            Use-DomainEntry

            $null = Invoke-Collector

            foreach ($attribute in $existingAttribute) {
                $expected = [scriptblock]::Create(
                    "`$Filter -eq '(objectClass=domainDNS)' -and " +
                    "`$Attributes -contains '$attribute'")
                Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                    -ParameterFilter $expected
            }
        }

        It 'keeps the values of the properties other tests read' {
            Use-DomainEntry

            $domain = Invoke-Collector

            $domain.MsDsMachineAccountQuota | Should -Be 0
            $domain.DomainMode | Should -Be 'Windows2016Domain'
            $domain.DnsRoot | Should -Be 'contoso.com'
            $domain.DomainSID.Value | Should -Be 'S-1-5-21-1-2-3'
        }
    }

    Context 'existing crossRef read' {
        It 'keeps reading the NetBIOS name from the crossRef of the domain' {
            Use-DomainEntry
            Use-CrossRef -CrossRef @(
                Get-CrossRef -NcName 'DC=child,DC=contoso,DC=com' -NetBios 'CHILD' -SystemFlags 3
                Get-CrossRef -NcName 'DC=contoso,DC=com' -NetBios 'CONTOSO' -SystemFlags 3
            )

            (Invoke-Collector).NetBIOSName | Should -BeExactly 'CONTOSO'
        }

        It 'keeps searching the Partitions container one level down for nCName and nETBIOSName' {
            Use-DomainEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $Filter -eq '(objectClass=crossRef)' -and
                $SearchBase -eq 'CN=Partitions,CN=Configuration,DC=contoso,DC=com' -and
                $Scope -eq 'OneLevel' -and $Attributes -contains 'nCName' -and
                $Attributes -contains 'nETBIOSName'
            }
        }
    }

    Context 'forest domain count' {
        It 'requests systemFlags on the crossRef search' {
            Use-DomainEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $Filter -eq '(objectClass=crossRef)' -and $Attributes -contains 'systemFlags'
            }
        }

        It 'counts the crossRefs that are domains and leaves out the other partitions' {
            Use-DomainEntry
            Use-CrossRef -CrossRef @(
                Get-CrossRef -NcName 'DC=contoso,DC=com' -SystemFlags 3
                Get-CrossRef -NcName 'DC=child,DC=contoso,DC=com' -SystemFlags '3'
                Get-CrossRef -NcName 'CN=Configuration,DC=contoso,DC=com' -SystemFlags 1
                Get-CrossRef -NcName 'CN=Schema,CN=Configuration,DC=contoso,DC=com' -SystemFlags 1
                Get-CrossRef -NcName 'DC=DomainDnsZones,DC=contoso,DC=com' -SystemFlags 5
                Get-CrossRef -NcName 'DC=other,DC=example' -SystemFlags 2
                Get-CrossRef -NcName 'DC=old,DC=example' -SystemFlags $null
            )

            (Invoke-Collector).ForestDomainCount | Should -BeExactly 2
        }

        It 'counts a domain crossRef that has more flags set' {
            Use-DomainEntry
            Use-CrossRef -CrossRef @(Get-CrossRef -NcName 'DC=contoso,DC=com' -SystemFlags 7)

            (Invoke-Collector).ForestDomainCount | Should -BeExactly 1
        }

        It 'ignores a systemFlags value that is not a number' {
            Use-DomainEntry
            Use-CrossRef -CrossRef @(
                Get-CrossRef -NcName 'DC=contoso,DC=com' -SystemFlags 3
                Get-CrossRef -NcName 'DC=odd,DC=example' -SystemFlags 'x'
            )

            $domain = Invoke-Collector

            $domain.ForestDomainCount | Should -BeExactly 1
            $domain.Name | Should -BeExactly 'contoso'
        }

        It 'returns $null when no crossRef is recognized as a domain' {
            Use-DomainEntry
            Use-CrossRef -CrossRef @(Get-CrossRef -NcName 'DC=contoso,DC=com' -SystemFlags $null)

            $null -eq (Invoke-Collector).ForestDomainCount | Should -Be $true
        }

        It 'adds the property after the existing ones' {
            Use-DomainEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names[-1] | Should -BeExactly 'ForestDomainCount'
        }
    }

    Context 'smart card password expiration' {
        It 'requests the msDS-ExpirePasswordsOnSmartCardOnlyAccounts attribute' {
            Use-DomainEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $Filter -eq '(objectClass=domainDNS)' -and
                $Attributes -contains 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'
            }
        }

        It 'returns $true when the attribute is TRUE' {
            Use-DomainEntry -Extra @{ 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' = 'TRUE' }

            (Invoke-Collector).ExpirePasswordsOnSmartCardOnlyAccounts | Should -Be $true
        }

        It 'returns $true whatever the case of the value' {
            Use-DomainEntry -Extra @{ 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' = 'true' }

            (Invoke-Collector).ExpirePasswordsOnSmartCardOnlyAccounts | Should -Be $true
        }

        It 'returns $false when the attribute is FALSE' {
            Use-DomainEntry -Extra @{ 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' = 'FALSE' }

            (Invoke-Collector).ExpirePasswordsOnSmartCardOnlyAccounts | Should -Be $false
        }

        It 'returns $null when the attribute is not set' {
            Use-DomainEntry

            $domain = Invoke-Collector

            $domain.PSObject.Properties.Name |
                Should -Contain 'ExpirePasswordsOnSmartCardOnlyAccounts'
            $null -eq $domain.ExpirePasswordsOnSmartCardOnlyAccounts | Should -Be $true
        }

        It 'returns $null for a value that is not a boolean' {
            Use-DomainEntry -Extra @{ 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' = 'maybe' }

            $null -eq (Invoke-Collector).ExpirePasswordsOnSmartCardOnlyAccounts | Should -Be $true
        }
    }

    Context 'domain update revision' {
        It 'reads the revision of the ActiveDirectoryUpdate object with a base search' {
            Use-DomainEntry
            Use-DomainUpdate

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $SearchBase -eq ('CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,' +
                    'DC=contoso,DC=com') -and
                $Scope -eq 'Base' -and $Attributes -contains 'revision'
            }
        }

        It 'returns the revision as a number' {
            Use-DomainEntry
            Use-DomainUpdate -Revision '15'

            $value = (Invoke-Collector).DomainUpdateRevision

            $value | Should -Be 15
            $value | Should -BeOfType [int]
        }

        It 'returns a revision that is already a number' {
            Use-DomainEntry
            Use-DomainUpdate -Revision 16

            (Invoke-Collector).DomainUpdateRevision | Should -Be 16
        }

        It 'returns $null when the object is not found' {
            Use-DomainEntry
            Use-DomainUpdate -Missing

            $domain = Invoke-Collector

            $domain.PSObject.Properties.Name | Should -Contain 'DomainUpdateRevision'
            $null -eq $domain.DomainUpdateRevision | Should -Be $true
        }

        It 'returns $null for a revision that is not a number' {
            Use-DomainEntry
            Use-DomainUpdate -Revision 'abc'

            $null -eq (Invoke-Collector).DomainUpdateRevision | Should -Be $true
        }

        It 'still returns the domain when the read fails' {
            Use-DomainEntry
            Use-DomainUpdate -Fail

            $domain = Invoke-Collector

            $null -eq $domain | Should -Be $false
            $domain.Name | Should -Be 'contoso'
            $domain.MsDsMachineAccountQuota | Should -Be 0
            $null -eq $domain.DomainUpdateRevision | Should -Be $true
        }

        It 'adds the property after the existing ones' {
            Use-DomainEntry
            Use-DomainUpdate

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names -contains 'DomainUpdateRevision' | Should -Be $true
        }
    }
}
