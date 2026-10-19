BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-026.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdKdsRootKeyPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdKdsRootKeyPermission {
        InModuleScope Maester { Test-MtAnssiAdKdsRootKeyPermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'

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
        param([string] $Rid, [uint32] $Mask, [string] $Sid = '')
        $trustee = "$script:domainSid-$Rid"
        if ($Sid) { $trustee = $Sid }
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = ''; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = $trustee
        }
    }

    function Use-Ad {
        param(
            [object[]] $Ace = @(),
            [switch] $NoObject,
            [switch] $Unreadable,
            [AllowNull()] [string] $DomainSid = $script:domainSid,
            [AllowNull()] [string] $ForestRootSid = $script:domainSid,
            [switch] $RootSidFails
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $admin = Get-PrincipalFixture -Name 'admin' -Rid '1100'
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID = $sidValue; DistinguishedName = 'DC=contoso,DC=com'
                DnsRoot = 'contoso.com'; Forest = 'contoso.com'
            }
            Users            = @($admin; Get-PrincipalFixture -Name 'key_op' -Rid '1105')
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
        Mock Get-MtAnssiAdNamingContextHead -ModuleName Maester -MockWith {
            'DC=contoso,DC=com'
            'CN=Configuration,DC=contoso,DC=com'
            'CN=Schema,CN=Configuration,DC=contoso,DC=com'
        }
        $aceList = $Ace
        if ($Unreadable) { $aceList = $null }
        $script:objects = @([PSCustomObject]@{
                DistinguishedName = ('CN=Master Root Keys,CN=Group Key Distribution Service,' +
                    'CN=Services,CN=Configuration,DC=contoso,DC=com')
                Name = 'Master Root Keys'
                ObjectClass = @('top', 'container'); OwnerSid = "$script:domainSid-512"
                Ace = $aceList
            })
        if ($NoObject) { $script:objects = @() }
        Mock Get-MtAnssiAdSearchSecurity -ModuleName Maester -MockWith { $script:objects }
    }

    function Get-Severity {
        param([string] $Expected)
        [scriptblock]::Create("`$Severity -eq '$Expected'")
    }
}

Describe 'Test-MtAnssiAdKdsRootKeyPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights and reports the most severe level' {
            Use-Ad -Ace @(Get-AceFixture -Rid '1200' -Mask 0xF01FF)

            Test-MtAnssiAdKdsRootKeyPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter {
                $Result -match ('^No principal outside the privileged set .* on the 1 KDS root' +
                    ' key objects')
            }
        }

        It 'fails with severity <Expected> for <Name>' -ForEach @(
            @{
                Name = 'a level 1 right'
                Mask = 0x40000
                Right = 'WriteDacl'
                Expected = 'Critical'
            }
            @{ Name = 'a level 2 right'; Mask = 0x1; Right = 'CreateChild'; Expected = 'High' }
        ) {
            Use-Ad -Ace @(Get-AceFixture -Rid '1105' -Mask $Mask)

            Test-MtAnssiAdKdsRootKeyPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
            $pattern = ('(?s)^1 dangerous rights on KDS root key objects.*\| Master Root Keys' +
                ' \| key_op \| ') + $Right
            $filter = [scriptblock]::Create("(`$Result -replace '\\', '') -match '$pattern'")
            Should -Invoke @detail -ParameterFilter $filter
        }
    }

    Context 'data read' {
        It 'reads the objects the test judges' {
            Use-Ad

            $null = Test-MtAnssiAdKdsRootKeyPermission

            Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($SearchBase -join ';') -eq 'CN=Services,CN=Configuration,DC=contoso,DC=com' -and
                $Scope -eq 'Subtree' -and
                $Filter -eq ('(|(&(objectClass=container)(cn=Master Root Keys))' +
                    '(objectClass=msKds-ProvRootKey))') -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 5 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups' -and $Categories -contains 'Trusts'
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

            { Test-MtAnssiAdKdsRootKeyPermission } | Should -Throw

        }

        It 'skips when the domain SID is missing' {
            Use-Ad -DomainSid $null

            $null -eq (Test-MtAnssiAdKdsRootKeyPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
        }

        It 'lets the exception reach the engine when <Command> fails' -ForEach @(
            @{ Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Command = 'Get-MtAnssiAdNamingContextHead' }
            @{ Command = 'Get-MtAnssiAdSearchSecurity' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdKdsRootKeyPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when the permissions of an object cannot be read' {
            Use-Ad -Unreadable

            $null -eq (Test-MtAnssiAdKdsRootKeyPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'could not be read'
            }
        }

        It 'is skipped when no KDS container is visible, not passed' {
            Use-Ad -NoObject

            $null -eq (Test-MtAnssiAdKdsRootKeyPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match '^No KDS container is visible'
            }
        }
    }

    Context 'forest root domain' {
        It 'trusts the Domain Admins of the forest root domain when run from a child domain' {
            $ace = Get-AceFixture -Rid '512' -Mask 0x40000 -Sid 'S-1-5-21-9-9-9-512'
            Use-Ad -ForestRootSid 'S-1-5-21-9-9-9' -Ace @($ace)

            Test-MtAnssiAdKdsRootKeyPermission | Should -Be $true
        }

        It 'still reports a Domain Admins group of any other domain' {
            $ace = Get-AceFixture -Rid '512' -Mask 0x40000 -Sid 'S-1-5-21-7-7-7-512'
            Use-Ad -ForestRootSid 'S-1-5-21-9-9-9' -Ace @($ace)

            Test-MtAnssiAdKdsRootKeyPermission | Should -Be $false
        }

        It 'takes the forest root SID from the domain and the trusts of the collected state' {
            Use-Ad

            $null = Test-MtAnssiAdKdsRootKeyPermission

            Should -Invoke Get-MtAnssiAdForestRootSid -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $Domain.DnsRoot -eq 'contoso.com' -and @($Trust).Count -eq 1 }
        }

        It 'lets the exception reach the engine when the forest root SID cannot be read' {
            Use-Ad -RootSidFails

            { Test-MtAnssiAdKdsRootKeyPermission } | Should -Throw '*LDAP failed*'

        }
    }
}
