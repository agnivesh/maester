BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:existingAttribute = @(
        'distinguishedName', 'name', 'sAMAccountName', 'userAccountControl', 'adminCount',
        'homeDirectory', 'badPasswordTime', 'lastLogonTimestamp', 'lockoutTime', 'logonHours',
        'userWorkstations', 'managedBy', 'manager', 'pwdLastSet', 'profilePath', 'scriptPath',
        'objectSid', 'sIDHistory', 'servicePrincipalName', 'whenCreated', 'whenChanged',
        'isCriticalSystemObject', 'primaryGroupID', 'msDS-SupportedEncryptionTypes'
    )

    $script:existingProperty = @(
        'DistinguishedName', 'Name', 'SamAccountName', 'Enabled', 'AdminCount',
        'CannotChangePassword', 'DoesNotRequirePreAuth', 'HomeDirectory', 'LastBadPasswordAttempt',
        'LastLogonDate', 'LockedOut', 'LogonHours', 'LogonWorkstations', 'ManagedBy', 'Manager',
        'PasswordExpired', 'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired',
        'ProfilePath', 'ScriptPath', 'Sid', 'SidHistory', 'ServicePrincipalName',
        'TrustedForDelegation', 'TrustedToAuthForDelegation', 'UseDESKeyOnly',
        'UserAccountControl', 'Created', 'Modified', 'IsCriticalSystemObject', 'PrimaryGroupId',
        'SupportedEncryptionTypes'
    )

    function Use-UserEntry {
        param([hashtable] $Extra = @{})
        $entry = [ordered]@{
            DistinguishedName    = 'CN=Alice,OU=Users,DC=contoso,DC=com'
            name                 = 'Alice'
            sAMAccountName       = 'alice'
            userAccountControl   = 66048
            adminCount           = 1
            lockoutTime          = 0
            objectSid            = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1105' }
            servicePrincipalName = @('HTTP/app.contoso.com', 'HTTP/app')
            isCriticalSystemObject = $false
        }
        foreach ($key in $Extra.Keys) { $entry[$key] = $Extra[$key] }
        $userEntry = [PSCustomObject]$entry
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith ({ $userEntry }.GetNewClosure())
    }

    function Invoke-Collector {
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            InModuleScope Maester -Parameters @{ Connection = $connection } {
                param($Connection)
                Get-MtLdapUser -Connection $Connection -SearchBase 'DC=contoso,DC=com'
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Get-MtLdapUser' {
    Context 'existing output' {
        It 'keeps every property it returned before, in the same order' {
            Use-UserEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            ($names | Select-Object -First $existingProperty.Count) -join ',' |
                Should -Be ($existingProperty -join ',')
        }

        It 'keeps requesting every attribute it requested before' {
            Use-UserEntry

            $null = Invoke-Collector

            foreach ($attribute in $existingAttribute) {
                $expected = [scriptblock]::Create("`$Attributes -contains '$attribute'")
                Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -ParameterFilter $expected
            }
        }

        It 'keeps the search filter that excludes computers' {
            Use-UserEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Filter -eq '(&(objectClass=user)(!(objectClass=computer)))' }
        }

        It 'keeps the values of the properties other tests read' {
            Use-UserEntry

            $user = Invoke-Collector

            $user.SamAccountName | Should -Be 'alice'
            $user.Enabled | Should -Be $true
            $user.PasswordNeverExpires | Should -Be $true
            $user.AdminCount | Should -Be 1
            $user.UserAccountControl | Should -Be 66048
            $user.Sid.Value | Should -Be 'S-1-5-21-1-2-3-1105'
            @($user.ServicePrincipalName).Count | Should -Be 2
            $user.IsCriticalSystemObject | Should -Be $false
        }

        It 'returns every entry of the search' {
            $first = [PSCustomObject]@{ DistinguishedName = 'CN=A,DC=x'; name = 'A' }
            $second = [PSCustomObject]@{ DistinguishedName = 'CN=B,DC=x'; name = 'B' }
            Mock Invoke-MtLdapSearch -ModuleName Maester `
                -MockWith ({ @($first, $second) }.GetNewClosure())

            @(Invoke-Collector).Count | Should -Be 2
        }
    }

    Context 'primary group' {
        It 'requests the primaryGroupID attribute' {
            Use-UserEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Attributes -contains 'primaryGroupID' }
        }

        It 'returns the primary group id' {
            Use-UserEntry -Extra @{ primaryGroupID = 513 }

            (Invoke-Collector).PrimaryGroupId | Should -Be 513
        }

        It 'returns the primary group id of a privileged group' {
            Use-UserEntry -Extra @{ primaryGroupID = 512 }

            (Invoke-Collector).PrimaryGroupId | Should -Be 512
        }

        It 'returns $null when the attribute has no value' {
            Use-UserEntry

            $user = Invoke-Collector

            $user.PSObject.Properties.Name | Should -Contain 'PrimaryGroupId'
            $null -eq $user.PrimaryGroupId | Should -Be $true
        }

        It 'adds the property after the existing ones' {
            Use-UserEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names.IndexOf('PrimaryGroupId') |
                Should -BeGreaterThan $names.IndexOf('IsCriticalSystemObject')
        }
    }

    Context 'supported encryption types' {
        It 'requests the msDS-SupportedEncryptionTypes attribute' {
            Use-UserEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Attributes -contains 'msDS-SupportedEncryptionTypes' }
        }

        It 'returns the value as a number when the collector gets text' {
            Use-UserEntry -Extra @{ 'msDS-SupportedEncryptionTypes' = '28' }

            $value = (Invoke-Collector).SupportedEncryptionTypes

            $value | Should -Be 28
            $value | Should -BeOfType [int]
        }

        It 'returns the value when it is already a number' {
            Use-UserEntry -Extra @{ 'msDS-SupportedEncryptionTypes' = 24 }

            (Invoke-Collector).SupportedEncryptionTypes | Should -Be 24
        }

        It 'returns 0 for an explicit zero' {
            Use-UserEntry -Extra @{ 'msDS-SupportedEncryptionTypes' = '0' }

            (Invoke-Collector).SupportedEncryptionTypes | Should -Be 0
        }

        It 'returns $null when the attribute has no value' {
            Use-UserEntry

            $user = Invoke-Collector

            $user.PSObject.Properties.Name | Should -Contain 'SupportedEncryptionTypes'
            $null -eq $user.SupportedEncryptionTypes | Should -Be $true
        }

        It 'returns $null for a value that is not a number and still returns the users' {
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

            $users = @(Invoke-Collector)

            $users.Count | Should -Be 2
            $null -eq $users[0].SupportedEncryptionTypes | Should -Be $true
            $users[1].SupportedEncryptionTypes | Should -Be 28
        }

        It 'adds the property after the primary group id' {
            Use-UserEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names.IndexOf('SupportedEncryptionTypes') |
                Should -BeGreaterThan $names.IndexOf('PrimaryGroupId')
        }
    }

    Context 'constrained delegation targets' {
        It 'requests the msDS-AllowedToDelegateTo attribute' {
            Use-UserEntry

            $null = Invoke-Collector

            Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Attributes -contains 'msDS-AllowedToDelegateTo' }
        }

        It 'returns every target service' {
            $targets = @('cifs/dc1.contoso.com', 'cifs/DC1')
            Use-UserEntry -Extra @{ 'msDS-AllowedToDelegateTo' = $targets }

            $value = (Invoke-Collector).AllowedToDelegateTo

            ,$value | Should -BeOfType [string[]]
            @($value) -join '|' | Should -BeExactly ($targets -join '|')
        }

        It 'returns an empty array when the attribute has no value' {
            Use-UserEntry

            $item = Invoke-Collector

            $item.PSObject.Properties.Name | Should -Contain 'AllowedToDelegateTo'
            @($item.AllowedToDelegateTo).Count | Should -Be 0
        }

        It 'adds the property after the existing ones' {
            Use-UserEntry

            $names = @((Invoke-Collector).PSObject.Properties.Name)

            $names.IndexOf('AllowedToDelegateTo') |
                Should -Be ($names.IndexOf('SupportedEncryptionTypes') + 1)
        }
    }
}
