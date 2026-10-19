BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-027.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdNamingContextPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdNamingContextPermission {
        InModuleScope Maester { Test-MtAnssiAdNamingContextPermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:replicate = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    $script:head = @('DC=contoso,DC=com', 'CN=Configuration,DC=contoso,DC=com')

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
        param([string] $Rid, [uint32] $Mask, [string] $ObjectType = '', [string] $Sid = '')
        $trustee = "$script:domainSid-$Rid"
        if ($Sid) { $trustee = $Sid }
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = $trustee
        }
    }

    function Use-Ad {
        param(
            [hashtable] $Ace = @{},
            [string[]] $Unreadable = @(),
            [AllowNull()] [string] $DomainSid = $script:domainSid,
            [AllowNull()] [string] $ForestRootSid = $script:domainSid,
            [switch] $RootSidFails
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $admin = Get-PrincipalFixture -Name 'admin' -Rid '1100'
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID = $sidValue; DnsRoot = 'contoso.com'; Forest = 'contoso.com'
            }
            Users            = @($admin; Get-PrincipalFixture -Name 'MSOL_1' -Rid '1105')
            Computers        = @(Get-PrincipalFixture -Name 'PC1$' -Rid '1106')
            Groups           = @(Get-PrincipalFixture -Name 'Tier0' -Rid '1200')
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
            Trusts           = @([PSCustomObject]@{ TrustPartner = 'x' })
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @([PSCustomObject]@{ Item = $admin })
            Unresolved = @()
            Group      = @('CN=Tier0,DC=contoso,DC=com')
        }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $rootSid = $ForestRootSid
        if ($RootSidFails) {
            Mock Get-MtAnssiAdForestRootSid -ModuleName Maester -MockWith { throw 'LDAP failed' }
        } else {
            Mock Get-MtAnssiAdForestRootSid -ModuleName Maester `
                -MockWith ({ $rootSid }.GetNewClosure())
        }
        $headList = $script:head
        Mock Get-MtAnssiAdNamingContextHead -ModuleName Maester `
            -MockWith ({ $headList }.GetNewClosure())
        $script:aceByName = $Ace
        $script:unreadableName = $Unreadable
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith {
            foreach ($dn in $DistinguishedName) {
                $name = ($dn -split ',')[0] -replace '^(CN|DC)=', ''
                $aceList = @($script:aceByName[$name])
                if ($name -in $script:unreadableName) { $aceList = $null }
                [PSCustomObject]@{
                    DistinguishedName = $dn; Name = $name; ObjectClass = @('top', 'domainDNS')
                    OwnerSid = "$script:domainSid-512"; Ace = $aceList
                }
            }
        }
    }

    function Get-Severity {
        param([string] $Expected)
        [scriptblock]::Create("`$Severity -eq '$Expected'")
    }
}

Describe 'Test-MtAnssiAdNamingContextPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights and reports the most severe level' {
            Use-Ad -Ace @{
                contoso       = @(
                    Get-AceFixture -Rid '1200' -Mask 0x100 -ObjectType $script:replicate
                )
                Configuration = @(Get-AceFixture -Rid '1100' -Mask 0xF01FF)
            }

            Test-MtAnssiAdNamingContextPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No principal outside the privileged set .* on the 2 naming context'
            }
        }

        It 'fails with severity <Expected> for <Name>' -ForEach @(
            @{ Name = 'secret replication'; Mask = 0x100; Replicate = $true; Expected = 'Critical' }
            @{ Name = 'creating child objects'; Mask = 0x1; Replicate = $false; Expected = 'High' }
        ) {
            $objectType = ''
            if ($Replicate) { $objectType = $script:replicate }
            $ace = Get-AceFixture -Rid '1105' -Mask $Mask -ObjectType $objectType
            Use-Ad -Ace @{ contoso = @($ace) }

            Test-MtAnssiAdNamingContextPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 dangerous rights on naming context roots' -and
                ($Result -replace '\\', '') -match '\| contoso \| MSOL_1 \|'
            }
        }

        It 'reports the most severe level of several rights on several roots' {
            Use-Ad -Ace @{
                contoso       = @(Get-AceFixture -Rid '1105' -Mask 0x1)
                Configuration = @(Get-AceFixture -Rid '1105' -Mask 0x40000)
            }

            Test-MtAnssiAdNamingContextPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter { $Result -match '^2 dangerous rights' }
        }
    }

    Context 'data read' {
        It 'reads the Domain, Users, Computers and Groups categories' {
            Use-Ad

            $null = Test-MtAnssiAdNamingContextPermission

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 5 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups' -and $Categories -contains 'Trusts'
            }
        }

        It 'reads every naming context root' {
            Use-Ad

            $null = Test-MtAnssiAdNamingContextPermission

            Should -Invoke Get-MtAnssiAdNamingContextHead -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
            Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($DistinguishedName -join ';') -eq
                'DC=contoso,DC=com;CN=Configuration,DC=contoso,DC=com' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
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

            { Test-MtAnssiAdNamingContextPermission } | Should -Throw

        }

        It 'skips when the domain SID is missing' {
            Use-Ad -DomainSid $null

            $null -eq (Test-MtAnssiAdNamingContextPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
        }

        It 'lets the exception reach the engine when <Name> fails' -ForEach @(
            @{ Name = 'the privileged list'; Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Name = 'the RootDSE read'; Command = 'Get-MtAnssiAdNamingContextHead' }
            @{ Name = 'the object read'; Command = 'Get-MtAnssiAdObjectSecurity' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdNamingContextPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when no naming context root is visible' {
            Use-Ad
            Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith { @() }
            $null -eq (Test-MtAnssiAdNamingContextPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match '^No naming context root is visible'
            }
        }

        It 'skips when the permissions of a root cannot be read' {
            Use-Ad -Unreadable @('Configuration')

            $null -eq (Test-MtAnssiAdNamingContextPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match
                '^No naming context root is visible, or the permissions of 1 of them'
            }
        }
    }

    Context 'forest root domain' {
        It 'trusts the Domain Admins of the forest root domain when run from a child domain' {
            $ace = Get-AceFixture -Rid '512' -Mask 0x40000 -Sid 'S-1-5-21-9-9-9-512'
            Use-Ad -ForestRootSid 'S-1-5-21-9-9-9' -Ace @{ contoso = @($ace) }

            Test-MtAnssiAdNamingContextPermission | Should -Be $true
        }

        It 'still reports a Domain Admins group of any other domain' {
            $ace = Get-AceFixture -Rid '512' -Mask 0x40000 -Sid 'S-1-5-21-7-7-7-512'
            Use-Ad -ForestRootSid 'S-1-5-21-9-9-9' -Ace @{ contoso = @($ace) }

            Test-MtAnssiAdNamingContextPermission | Should -Be $false
        }

        It 'takes the forest root SID from the domain and the trusts of the collected state' {
            Use-Ad

            $null = Test-MtAnssiAdNamingContextPermission

            Should -Invoke Get-MtAnssiAdForestRootSid -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Domain.DnsRoot -eq 'contoso.com' -and @($Trust).Count -eq 1 }
        }

        It 'lets the exception reach the engine when the forest root SID cannot be read' {
            Use-Ad -RootSidFails

            { Test-MtAnssiAdNamingContextPermission } | Should -Throw '*LDAP failed*'

        }
    }
}
