BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function ConvertTo-BinarySid {
        param([string] $Sid)
        $parts = $Sid -split '-'
        $bytes = [System.Collections.Generic.List[byte]]::new()
        $bytes.Add([byte]$parts[1])
        $bytes.Add([byte]($parts.Count - 3))
        $bytes.AddRange([byte[]](0, 0, 0, 0, 0, [byte]$parts[2]))
        for ($index = 3; $index -lt $parts.Count; $index++) {
            $bytes.AddRange([BitConverter]::GetBytes([uint32]$parts[$index]))
        }
        , $bytes.ToArray()
    }

    function ConvertTo-BinaryDescriptor {
        param([string] $Owner, [string] $Trustee, [uint32] $Mask)
        $ownerBytes = ConvertTo-BinarySid -Sid $Owner
        $trusteeBytes = ConvertTo-BinarySid -Sid $Trustee
        $bytes = [System.Collections.Generic.List[byte]]::new()
        $bytes.AddRange([byte[]](1, 0, 4, 0x80))
        $bytes.AddRange([BitConverter]::GetBytes([uint32]20))
        $bytes.AddRange([BitConverter]::GetBytes([uint32]0))
        $bytes.AddRange([BitConverter]::GetBytes([uint32]0))
        $bytes.AddRange([BitConverter]::GetBytes([uint32](20 + $ownerBytes.Length)))
        $bytes.AddRange($ownerBytes)
        $aceSize = 8 + $trusteeBytes.Length
        $bytes.AddRange([byte[]](2, 0))
        $bytes.AddRange([BitConverter]::GetBytes([uint16](8 + $aceSize)))
        $bytes.AddRange([byte[]](1, 0, 0, 0))
        $bytes.AddRange([byte[]](0, 0))
        $bytes.AddRange([BitConverter]::GetBytes([uint16]$aceSize))
        $bytes.AddRange([BitConverter]::GetBytes($Mask))
        $bytes.AddRange($trusteeBytes)
        , $bytes.ToArray()
    }

    function Get-RawEntryFixture {
        param([byte[]] $Descriptor)
        $attributes = @{}
        if ($null -ne $Descriptor) {
            $attribute = [PSCustomObject]@{ Value = $Descriptor }
            $attribute | Add-Member -MemberType ScriptMethod -Name GetValues -Value {
                param($Type)
                $null = $Type
                , @(, $this.Value)
            }
            $attributes['nTSecurityDescriptor'] = $attribute
        }
        [PSCustomObject]@{ Attributes = $attributes }
    }

    function Invoke-Query {
        param([hashtable] $Parameter = @{})
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
        try {
            $parameters = @{ Connection = $connection; Parameter = $Parameter }
            InModuleScope Maester -Parameters $parameters {
                param($Connection, $Parameter)
                @(Get-MtLdapObjectSecurity -Connection $Connection -SearchBase 'CN=x,DC=x' `
                        @Parameter)
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Describe 'Get-MtLdapObjectSecurity' {
    It 'returns the name, classes, owner, entries and extra attributes of each object' {
        $script:descriptor = ConvertTo-BinaryDescriptor -Owner 'S-1-5-21-1-2-3-512' `
            -Trustee 'S-1-5-21-1-2-3-1105' -Mask 0x40000
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                DistinguishedName = 'OU=a,DC=x'
                name              = 'a'
                objectClass       = @('top', 'organizationalUnit')
                gPLink            = '[LDAP://cn={1},cn=policies,cn=system,DC=x;0]'
                DirectoryEntry    = Get-RawEntryFixture -Descriptor $script:descriptor
            }
        }

        $result = Invoke-Query -Parameter @{ Attribute = @('gPLink', 'gPOptions') }

        $result.Count | Should -Be 1
        $result[0].DistinguishedName | Should -BeExactly 'OU=a,DC=x'
        $result[0].Name | Should -BeExactly 'a'
        $result[0].ObjectClass -join ',' | Should -BeExactly 'top,organizationalUnit'
        $result[0].OwnerSid | Should -BeExactly 'S-1-5-21-1-2-3-512'
        @($result[0].Ace).Count | Should -Be 1
        $result[0].Ace[0].Sid | Should -BeExactly 'S-1-5-21-1-2-3-1105'
        $result[0].Ace[0].Mask | Should -Be 0x40000
        $result[0].Attribute['gPLink'] |
            Should -BeExactly '[LDAP://cn={1},cn=policies,cn=system,DC=x;0]'
        $result[0].Attribute.Contains('gPOptions') | Should -Be $true
        $null -eq $result[0].Attribute['gPOptions'] | Should -Be $true
    }

    It 'reads the base object alone with the owner and DACL flags by default' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { }

        $null = Invoke-Query

        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            $SearchBase -eq 'CN=x,DC=x' -and $Scope -eq 'Base' -and
            $Filter -eq '(objectClass=*)' -and
            $PageSize -eq 0 -and $ReturnDirectoryEntry.IsPresent -and
            [int]$SecurityDescriptorFlags -eq 5 -and
            ($Attributes -join ',') -eq 'distinguishedName,name,objectClass,nTSecurityDescriptor'
        }
    }

    It 'pages a <Scope> search with the given filter and extra attributes' -ForEach @(
        @{ Scope = 'OneLevel' }
        @{ Scope = 'Subtree' }
    ) {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { }

        $null = Invoke-Query -Parameter @{
            Scope = $Scope; Filter = '(objectClass=secret)'; Attribute = @('gPLink')
        }

        $expected = "`$Scope -eq '$Scope' -and `$PageSize -eq 1000 -and " +
        "`$Filter -eq '(objectClass=secret)' -and (`$Attributes -join ',') -eq " +
        "'distinguishedName,name,objectClass,nTSecurityDescriptor,gPLink'"
        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter ([scriptblock]::Create($expected))
    }

    It 'returns no entries and no owner when the server returned no descriptor' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                DistinguishedName = 'CN=b,DC=x'; name = 'b'; objectClass = 'container'
                DirectoryEntry    = Get-RawEntryFixture -Descriptor $null
            }
        }

        $result = Invoke-Query

        $null -eq $result[0].Ace | Should -Be $true
        $null -eq $result[0].OwnerSid | Should -Be $true
        $result[0].ObjectClass -join ',' | Should -BeExactly 'container'
    }

    It 'returns no entries when the result carries no raw attributes' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                DistinguishedName = 'CN=c,DC=x'; name = 'c'; objectClass = 'container'
            }
        }

        $null -eq (Invoke-Query)[0].Ace | Should -Be $true
    }

    It 'lets a failed search throw' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith { throw 'LDAP search failed' }

        { Invoke-Query } | Should -Throw -ExpectedMessage 'LDAP search failed'
    }

    It 'lets a malformed descriptor throw' {
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                DistinguishedName = 'CN=d,DC=x'; name = 'd'; objectClass = 'container'
                DirectoryEntry    = Get-RawEntryFixture -Descriptor ([byte[]](1, 0, 4))
            }
        }

        { Invoke-Query } | Should -Throw '*fewer than its header*'
    }
}
