BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:existingAttribute = @(
        'distinguishedName', 'name', 'sAMAccountName', 'userAccountControl', 'operatingSystem',
        'operatingSystemVersion', 'dNSHostName', 'whenCreated', 'whenChanged', 'lastLogonTimestamp',
        'pwdLastSet', 'servicePrincipalName', 'primaryGroupID', 'objectSid',
        'isCriticalSystemObject', 'managedBy', 'sIDHistory', 'msDS-SupportedEncryptionTypes',
        'msDS-KrbTgtLink', 'objectClass', 'msDS-NeverRevealGroup', 'msDS-RevealOnDemandGroup',
        'msDS-AllowedToDelegateTo'
    )

    $script:existingProperty = @(
        'DistinguishedName', 'Name', 'SamAccountName', 'Enabled', 'OperatingSystem',
        'OperatingSystemVersion', 'DnsHostName', 'Created', 'Modified', 'LastLogonDate',
        'PasswordLastSet', 'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired',
        'TrustedForDelegation', 'TrustedToAuthForDelegation', 'ServicePrincipalName',
        'PrimaryGroupId', 'Sid', 'UserAccountControl', 'IsCriticalSystemObject', 'ManagedBy',
        'SidHistory', 'SupportedEncryptionTypes', 'KrbTgtLink', 'ObjectClass', 'NeverRevealGroup',
        'RevealOnDemandGroup', 'AllowedToDelegateTo'
    )

    function Use-ComputerEntry {
        param([hashtable] $Extra = @{})
        $entry = [ordered]@{
            DistinguishedName      = 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com'
            name                   = 'DC1'
            sAMAccountName         = 'DC1$'
            userAccountControl     = 532480
            operatingSystem        = 'Windows Server 2022 Standard'
            operatingSystemVersion = '10.0 (20348)'
            dNSHostName            = 'dc1.contoso.com'
            primaryGroupID         = 516
            objectSid              = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1000' }
            servicePrincipalName   = @('ldap/dc1.contoso.com')
            isCriticalSystemObject = $true
        }
        foreach ($key in $Extra.Keys) { $entry[$key] = $Extra[$key] }
        $computerEntry = [PSCustomObject]$entry
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith ({ $computerEntry }.GetNewClosure())
    }

    function ConvertTo-BinaryDescriptor {
        param([string[]] $Allow = @(), [string[]] $Deny = @())
        $entries = [System.Collections.Generic.List[byte]]::new()
        $count = 0
        foreach ($item in @($Deny | ForEach-Object { @{ Type = 1; Sid = $_ } }) +
            @($Allow | ForEach-Object { @{ Type = 0; Sid = $_ } })) {
            $parts = $item.Sid -split '-'
            $sid = [System.Collections.Generic.List[byte]]::new()
            $sid.AddRange([byte[]](1, ($parts.Count - 3), 0, 0, 0, 0, 0, [byte]$parts[2]))
            for ($index = 3; $index -lt $parts.Count; $index++) {
                $sid.AddRange([BitConverter]::GetBytes([uint32]$parts[$index]))
            }
            $entries.AddRange([byte[]]($item.Type, 0))
            $entries.AddRange([BitConverter]::GetBytes([uint16](8 + $sid.Count)))
            $entries.AddRange([BitConverter]::GetBytes([uint32]0xF01FF))
            $entries.AddRange($sid)
            $count++
        }
        $bytes = [System.Collections.Generic.List[byte]]::new()
        $bytes.AddRange([byte[]](1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0))
        $bytes.AddRange([byte[]](2, 0))
        $bytes.AddRange([BitConverter]::GetBytes([uint16](8 + $entries.Count)))
        $bytes.AddRange([BitConverter]::GetBytes([uint16]$count))
        $bytes.AddRange([byte[]](0, 0))
        $bytes.AddRange($entries)
        , $bytes.ToArray()
    }

    function Invoke-Collector {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection } {
                param($Connection)
                Get-MtLdapComputer -Connection $Connection -SearchBase 'DC=contoso,DC=com'
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Get-MtLdapComputer' {
    Context 'existing output' {
        It 'keeps every property it returned before, in the same order' {
            Use-ComputerEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            ($names | Select-Object -First $existingProperty.Count) -join ',' |
                Should -BeExactly ($existingProperty -join ',')
        }

        It 'keeps requesting every attribute it requested before' {
            Use-ComputerEntry

            $null = Invoke-Collector

            foreach ($attribute in $existingAttribute) {
                $expected = [scriptblock]::Create("`$Attributes -contains '$attribute'")
                Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -ParameterFilter $expected
            }
        }

        It 'keeps the search filter for computer objects' {
            Use-ComputerEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Filter -eq '(objectClass=computer)' }
        }

        It 'keeps the values of the properties other tests read' {
            Use-ComputerEntry

            $computer = Invoke-Collector

            $computer.Name | Should -Be 'DC1'
            $computer.SamAccountName | Should -Be 'DC1$'
            $computer.Enabled | Should -Be $true
            $computer.PrimaryGroupId | Should -Be 516
            $computer.UserAccountControl | Should -Be 532480
            $computer.TrustedForDelegation | Should -Be $true
            $computer.OperatingSystem | Should -Be 'Windows Server 2022 Standard'
            $computer.DnsHostName | Should -Be 'dc1.contoso.com'
            $computer.Sid.Value | Should -Be 'S-1-5-21-1-2-3-1000'
            @($computer.ServicePrincipalName).Count | Should -Be 1
            $computer.IsCriticalSystemObject | Should -Be $true
        }

        It 'returns every entry of the search' {
            $first = [PSCustomObject]@{ DistinguishedName = 'CN=A,DC=x'; name = 'A' }
            $second = [PSCustomObject]@{ DistinguishedName = 'CN=B,DC=x'; name = 'B' }
            Mock Invoke-MtLdapSearch -ModuleName Maester `
                -MockWith ({ @($first, $second) }.GetNewClosure())

            @(Invoke-Collector).Count | Should -Be 2
        }
    }

    Context 'supported encryption types' {
        It 'requests the msDS-SupportedEncryptionTypes attribute' {
            Use-ComputerEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Attributes -contains 'msDS-SupportedEncryptionTypes' }
        }

        It 'returns the value as a number when the collector gets text' {
            Use-ComputerEntry -Extra @{ 'msDS-SupportedEncryptionTypes' = '28' }

            $value = (Invoke-Collector).SupportedEncryptionTypes

            $value | Should -Be 28
            $value | Should -BeOfType [int]
        }

        It 'returns the value when it is already a number' {
            Use-ComputerEntry -Extra @{ 'msDS-SupportedEncryptionTypes' = 24 }

            (Invoke-Collector).SupportedEncryptionTypes | Should -Be 24
        }

        It 'returns 0 for an explicit zero' {
            Use-ComputerEntry -Extra @{ 'msDS-SupportedEncryptionTypes' = '0' }

            (Invoke-Collector).SupportedEncryptionTypes | Should -Be 0
        }

        It 'returns $null when the attribute has no value' {
            Use-ComputerEntry

            $computer = Invoke-Collector

            $computer.PSObject.Properties.Name | Should -Contain 'SupportedEncryptionTypes'
            $null -eq $computer.SupportedEncryptionTypes | Should -Be $true
        }

        It 'returns $null for a value that is not a number and still returns the computers' {
            $bad = [PSCustomObject]@{
                DistinguishedName = 'CN=Bad,DC=x'; name = 'Bad'
                'msDS-SupportedEncryptionTypes' = 'abc'
            }
            $good = [PSCustomObject]@{
                DistinguishedName = 'CN=Good,DC=x'; name = 'Good'
                'msDS-SupportedEncryptionTypes' = '28'
            }
            Mock Invoke-MtLdapSearch -ModuleName Maester `
                -MockWith ({ @($bad, $good) }.GetNewClosure())

            $computers = @(Invoke-Collector)

            $computers.Count | Should -Be 2
            $null -eq $computers[0].SupportedEncryptionTypes | Should -Be $true
            $computers[1].SupportedEncryptionTypes | Should -Be 28
        }

        It 'adds the property after the existing ones' {
            Use-ComputerEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names.IndexOf('SupportedEncryptionTypes') |
                Should -BeGreaterThan $names.IndexOf('SidHistory')
        }
    }

    Context 'krbtgt link' {
        It 'requests the msDS-KrbTgtLink attribute' {
            Use-ComputerEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Attributes -contains 'msDS-KrbTgtLink' }
        }

        It 'returns the distinguished name of the krbtgt account' {
            $dn = 'CN=krbtgt_12345,CN=Users,DC=contoso,DC=com'
            Use-ComputerEntry -Extra @{ 'msDS-KrbTgtLink' = $dn }

            (Invoke-Collector).KrbTgtLink | Should -BeExactly $dn
        }

        It 'returns $null, not an empty string, when the attribute has no value' {
            Use-ComputerEntry

            $computer = Invoke-Collector

            $computer.PSObject.Properties.Name | Should -Contain 'KrbTgtLink'
            $null -eq $computer.KrbTgtLink | Should -Be $true
        }

        It 'adds the property after the supported encryption types' {
            Use-ComputerEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names.IndexOf('KrbTgtLink') |
                Should -BeGreaterThan $names.IndexOf('SupportedEncryptionTypes')
        }
    }

    Context 'object class' {
        It 'requests the objectClass attribute' {
            Use-ComputerEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Attributes -contains 'objectClass' }
        }

        It 'returns every class of the object' {
            $classes = @('top', 'person', 'organizationalPerson', 'user', 'computer',
                'msDS-GroupManagedServiceAccount')
            Use-ComputerEntry -Extra @{ objectClass = $classes }

            $value = @((Invoke-Collector).ObjectClass)

            $value -join ',' | Should -BeExactly ($classes -join ',')
        }

        It 'returns a single class as an array' {
            Use-ComputerEntry -Extra @{ objectClass = 'computer' }

            $value = (Invoke-Collector).ObjectClass

            ,$value | Should -BeOfType [string[]]
            @($value).Count | Should -Be 1
        }

        It 'returns an empty array when the attribute has no value' {
            Use-ComputerEntry

            $computer = Invoke-Collector

            $computer.PSObject.Properties.Name | Should -Contain 'ObjectClass'
            @($computer.ObjectClass).Count | Should -Be 0
        }

        It 'adds the property after the krbtgt link' {
            Use-ComputerEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names.IndexOf('ObjectClass') | Should -BeGreaterThan $names.IndexOf('KrbTgtLink')
        }
    }

    Context 'password replication policy' {
        It 'requests the msDS-NeverRevealGroup and msDS-RevealOnDemandGroup attributes' {
            Use-ComputerEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $Attributes -contains 'msDS-NeverRevealGroup' -and
                $Attributes -contains 'msDS-RevealOnDemandGroup'
            }
        }

        It 'returns every entry of both lists' {
            $never = @('CN=Administrators,CN=Builtin,DC=contoso,DC=com',
                'CN=Denied RODC Password Replication Group,CN=Users,DC=contoso,DC=com')
            $reveal = 'CN=Allowed RODC Password Replication Group,CN=Users,DC=contoso,DC=com'
            Use-ComputerEntry -Extra @{
                'msDS-NeverRevealGroup'    = $never
                'msDS-RevealOnDemandGroup' = $reveal
            }

            $computer = Invoke-Collector

            @($computer.NeverRevealGroup) -join '|' | Should -BeExactly ($never -join '|')
            ,$computer.RevealOnDemandGroup | Should -BeOfType [string[]]
            @($computer.RevealOnDemandGroup) -join '|' | Should -BeExactly $reveal
        }

        It 'returns empty arrays when the attributes have no value' {
            Use-ComputerEntry

            $computer = Invoke-Collector

            $computer.PSObject.Properties.Name | Should -Contain 'NeverRevealGroup'
            $computer.PSObject.Properties.Name | Should -Contain 'RevealOnDemandGroup'
            @($computer.NeverRevealGroup).Count | Should -Be 0
            @($computer.RevealOnDemandGroup).Count | Should -Be 0
        }

        It 'adds the properties after the object class, in this order' {
            Use-ComputerEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names.IndexOf('NeverRevealGroup') | Should -Be ($names.IndexOf('ObjectClass') + 1)
            $names.IndexOf('RevealOnDemandGroup') | Should -Be ($names.IndexOf('ObjectClass') + 2)
        }
    }

    Context 'constrained delegation targets' {
        It 'requests the msDS-AllowedToDelegateTo attribute' {
            Use-ComputerEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Attributes -contains 'msDS-AllowedToDelegateTo' }
        }

        It 'returns every target service' {
            $targets = @('cifs/dc1.contoso.com', 'cifs/DC1')
            Use-ComputerEntry -Extra @{ 'msDS-AllowedToDelegateTo' = $targets }

            $value = (Invoke-Collector).AllowedToDelegateTo

            ,$value | Should -BeOfType [string[]]
            @($value) -join '|' | Should -BeExactly ($targets -join '|')
        }

        It 'returns an empty array when the attribute has no value' {
            Use-ComputerEntry

            $item = Invoke-Collector

            $item.PSObject.Properties.Name | Should -Contain 'AllowedToDelegateTo'
            @($item.AllowedToDelegateTo).Count | Should -Be 0
        }

        It 'adds the property after the existing ones' {
            Use-ComputerEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names.IndexOf('AllowedToDelegateTo') |
                Should -Be ($names.IndexOf('RevealOnDemandGroup') + 1)
        }
    }

    Context 'resource-based constrained delegation' {
        It 'requests the msDS-AllowedToActOnBehalfOfOtherIdentity attribute' {
            Use-ComputerEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $Attributes -contains 'msDS-AllowedToActOnBehalfOfOtherIdentity'
            }
        }

        It 'returns the SIDs of the allow entries of the descriptor' {
            $bytes = ConvertTo-BinaryDescriptor -Allow 'S-1-5-21-1-2-3-1105', 'S-1-5-21-1-2-3-1106'
            Use-ComputerEntry -Extra @{ 'msDS-AllowedToActOnBehalfOfOtherIdentity' = $bytes }

            $value = (Invoke-Collector).AllowedToActOnBehalfOfOtherIdentity

            @($value) -join ',' | Should -BeExactly 'S-1-5-21-1-2-3-1105,S-1-5-21-1-2-3-1106'
        }

        It 'leaves out the deny entries' {
            $bytes = ConvertTo-BinaryDescriptor -Allow 'S-1-5-21-1-2-3-1105' `
                -Deny 'S-1-5-21-1-2-3-1107'
            Use-ComputerEntry -Extra @{ 'msDS-AllowedToActOnBehalfOfOtherIdentity' = $bytes }

            @((Invoke-Collector).AllowedToActOnBehalfOfOtherIdentity) -join ',' |
                Should -BeExactly 'S-1-5-21-1-2-3-1105'
        }

        It 'returns $null when the attribute is not set' {
            Use-ComputerEntry

            $computer = Invoke-Collector

            $computer.PSObject.Properties.Name |
                Should -Contain 'AllowedToActOnBehalfOfOtherIdentity'
            $null -eq $computer.AllowedToActOnBehalfOfOtherIdentity | Should -Be $true
        }

        It 'returns an empty array, not $null, for a descriptor without allow entries' {
            $bytes = ConvertTo-BinaryDescriptor
            Use-ComputerEntry -Extra @{ 'msDS-AllowedToActOnBehalfOfOtherIdentity' = $bytes }

            $value = (Invoke-Collector).AllowedToActOnBehalfOfOtherIdentity

            $null -eq $value | Should -Be $false
            @($value).Count | Should -Be 0
        }

        It 'returns an empty array for a value it cannot parse and still returns the computers' {
            $bad = [PSCustomObject]@{
                DistinguishedName = 'CN=Bad,DC=x'; name = 'Bad'
                'msDS-AllowedToActOnBehalfOfOtherIdentity' = [byte[]]@(1, 2, 3)
            }
            $good = [PSCustomObject]@{ DistinguishedName = 'CN=Good,DC=x'; name = 'Good' }
            Mock Invoke-MtLdapSearch -ModuleName Maester `
                -MockWith ({ @($bad, $good) }.GetNewClosure())

            $computers = @(Invoke-Collector)

            $computers.Count | Should -Be 2
            $null -eq $computers[0].AllowedToActOnBehalfOfOtherIdentity | Should -Be $false
            @($computers[0].AllowedToActOnBehalfOfOtherIdentity).Count | Should -Be 0
            $null -eq $computers[1].AllowedToActOnBehalfOfOtherIdentity | Should -Be $true
        }

        It 'adds the property after the delegation targets' {
            Use-ComputerEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names.IndexOf('AllowedToActOnBehalfOfOtherIdentity') |
                Should -Be ($names.IndexOf('AllowedToDelegateTo') + 1)
        }
    }
}
