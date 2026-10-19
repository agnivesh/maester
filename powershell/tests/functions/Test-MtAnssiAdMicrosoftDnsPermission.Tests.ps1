BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-029.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdMicrosoftDnsPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdMicrosoftDnsPermission {
        InModuleScope Maester { Test-MtAnssiAdMicrosoftDnsPermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:systemDns = 'CN=MicrosoftDNS,CN=System,DC=contoso,DC=com'

    function Get-PrincipalFixture {
        param([string] $Name, [string] $Rid)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Name              = $Name
            SamAccountName    = $Name
            Sid               = [PSCustomObject]@{ Value = "$script:domainSid-$Rid" }
        }
    }

    function Get-AceFixture {
        param([string] $Rid, [uint32] $Mask)
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = ''; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = "$script:domainSid-$Rid"
        }
    }

    function Use-Ad {
        param(
            [object[]] $Ace = @(),
            [switch] $NoContainer,
            [switch] $Unreadable,
            [AllowNull()] [string] $DomainSid = $script:domainSid,
            [AllowNull()] [string] $DomainDn = 'DC=contoso,DC=com'
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $admin = Get-PrincipalFixture -Name 'admin' -Rid '1100'
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID = $sidValue; DistinguishedName = $DomainDn
            }
            Users            = @($admin)
            Computers        = @(Get-PrincipalFixture -Name 'PC1$' -Rid '1106')
            Groups           = @(
                Get-PrincipalFixture -Name 'Tier0' -Rid '1200'
                Get-PrincipalFixture -Name 'DnsAdmins' -Rid '1101'
            )
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @([PSCustomObject]@{ Item = $admin })
            Unresolved = @()
            Group      = @('CN=Tier0,DC=contoso,DC=com')
        }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        Mock Get-MtAnssiAdNamingContextHead -ModuleName Maester -MockWith {
            'DC=contoso,DC=com'
            'CN=Configuration,DC=contoso,DC=com'
            'DC=DomainDnsZones,DC=contoso,DC=com'
            'DC=ForestDnsZones,DC=contoso,DC=com'
        }
        $aceList = $Ace
        if ($Unreadable) { $aceList = $null }
        $objects = @([PSCustomObject]@{
                DistinguishedName = $script:systemDns; Name = 'MicrosoftDNS'
                ObjectClass = @('top', 'container'); OwnerSid = "$script:domainSid-512"
                Ace = $aceList
            })
        if ($NoContainer) { $objects = @() }
        Mock Get-MtAnssiAdSearchSecurity -ModuleName Maester `
            -MockWith ({ $objects }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdMicrosoftDnsPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights' {
            Use-Ad -Ace @(Get-AceFixture -Rid '1200' -Mask 0xF01FF)

            Test-MtAnssiAdMicrosoftDnsPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No principal outside .* on the 1 MicrosoftDNS containers'
            }
        }

        It 'fails for the rights of DnsAdmins, Critical, with the container name' -ForEach @(
            @{ Mask = 0xF01FF; Right = 'GenericAll' }
            @{ Mask = 0x1; Right = 'CreateChild' }
        ) {
            Use-Ad -Ace @(Get-AceFixture -Rid '1101' -Mask $Mask)

            Test-MtAnssiAdMicrosoftDnsPermission | Should -Be $false

            $pattern = '^1 dangerous rights on MicrosoftDNS containers.*' +
            '\| CN=MicrosoftDNS,CN=System \| DnsAdmins \| ' + $Right +
            ' \| Critical \|'
            $filter = [scriptblock]::Create("(`$Result -replace '\\', '') -match '(?s)$pattern'")
            Should -Invoke @detail -ParameterFilter $filter
        }
    }

    Context 'data read' {
        It 'looks below CN=System and the DNS partitions only' {
            Use-Ad

            $null = Test-MtAnssiAdMicrosoftDnsPermission

            Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 `
                -Exactly `
                -ParameterFilter {
                $Scope -eq 'OneLevel' -and
                    $Filter -eq '(&(objectClass=container)(cn=MicrosoftDNS))' -and
                ($SearchBase -join ';') -eq ('CN=System,DC=contoso,DC=com;' +
                    'DC=DomainDnsZones,DC=contoso,DC=com;DC=ForestDnsZones,DC=contoso,DC=com') -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdNamingContextHead -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'admin' -and
                @($Computer)[0].Name -eq 'PC1$' -and @($Group)[0].Name -eq 'Tier0' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }
    }

    Context 'skips' {
        It 'lets the exception reach the engine when the state cannot be read' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

            { Test-MtAnssiAdMicrosoftDnsPermission } | Should -Throw

        }

        It 'skips when the domain <Name> is missing' -ForEach @(
            @{ Name = 'SID'; Sid = $null; Dn = 'DC=contoso,DC=com' }
            @{ Name = 'name'; Sid = 'S-1-5-21-1-2-3'; Dn = $null }
        ) {
            Use-Ad -DomainSid $Sid -DomainDn $Dn

            $null -eq (Test-MtAnssiAdMicrosoftDnsPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID or name'
            }
        }

        It 'lets the exception reach the engine when <Command> fails' -ForEach @(
            @{ Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Command = 'Get-MtAnssiAdNamingContextHead' }
            @{ Command = 'Get-MtAnssiAdSearchSecurity' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdMicrosoftDnsPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when no MicrosoftDNS container is visible' {
            Use-Ad -NoContainer

            $null -eq (Test-MtAnssiAdMicrosoftDnsPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match 'No MicrosoftDNS container'
            }
            Should -Invoke Add-MtTestResultDetail -ModuleName Maester -Times 1 -Exactly
        }

        It 'skips when the permissions of a container cannot be read' {
            Use-Ad -Unreadable

            $null -eq (Test-MtAnssiAdMicrosoftDnsPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'could not be read'
            }
        }
    }
}
