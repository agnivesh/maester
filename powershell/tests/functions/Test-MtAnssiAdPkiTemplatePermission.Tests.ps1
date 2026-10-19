BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-002.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPkiTemplatePermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPkiTemplatePermission {
        InModuleScope Maester { Test-MtAnssiAdPkiTemplatePermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $script:nameFlag = 'ea1dddc4-60ff-416e-8cc0-17cee534bce7'

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
        param([string] $Rid, [uint32] $Mask, [string] $ObjectType = '')
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = "$script:domainSid-$Rid"
        }
    }

    function Get-TemplateFixture {
        param([string] $Name, [AllowNull()] [object[]] $Ace, [string] $Owner = '512')
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=Certificate Templates,CN=Public Key Services"
            Name              = $Name
            ObjectClass       = @('top', 'pKICertificateTemplate')
            OwnerSid          = "$script:domainSid-$Owner"
            Ace               = $Ace
        }
    }

    function Use-Ad {
        param(
            [object[]] $Template = @(Get-TemplateFixture -Name 'User' -Ace @()),
            [AllowNull()] [string] $DomainSid = $script:domainSid,
            [AllowNull()] [string] $DnsRoot = 'contoso.com',
            [AllowNull()] [string] $Forest = 'Contoso.com',
            [object[]] $Unresolved = @()
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $admin = Get-PrincipalFixture -Name 'admin' -Rid '1100'
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID = $sidValue; DnsRoot = $DnsRoot; Forest = $Forest
            }
            Users            = @($admin; Get-PrincipalFixture -Name 'pki_op' -Rid '1105')
            Computers        = @(Get-PrincipalFixture -Name 'PC1$' -Rid '1106')
            Groups           = @(Get-PrincipalFixture -Name 'Tier0' -Rid '1200')
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @([PSCustomObject]@{ Item = $admin })
            Unresolved = $Unresolved
            Group      = @('CN=Tier0,DC=contoso,DC=com')
        }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        Mock Get-MtAnssiAdNamingContextHead -ModuleName Maester -MockWith {
            'DC=contoso,DC=com'
            'CN=Configuration,DC=contoso,DC=com'
            'CN=Schema,CN=Configuration,DC=contoso,DC=com'
        }
        $script:templates = $Template
        $script:services = @([PSCustomObject]@{
                DistinguishedName = 'CN=Contoso CA,CN=Enrollment Services'; Name = 'Contoso CA'
                ObjectClass = @('top', 'pKIEnrollmentService'); OwnerSid = "$script:domainSid-512"
                Ace = @(); Attribute = [ordered]@{ certificateTemplates = @('user', 'Machine') }
            })
        Mock Get-MtAnssiAdSearchSecurity -ModuleName Maester -MockWith {
            if ($Filter -eq '(objectClass=pKIEnrollmentService)') { return $script:services }
            $script:templates
        }
    }

    function Get-Severity {
        param([string] $Expected)
        [scriptblock]::Create("`$Severity -eq '$Expected'")
    }

    function Get-ResultFilter {
        param([string] $Pattern)
        [scriptblock]::Create("(`$Result -replace '\\', '') -match '$Pattern'")
    }
}

Describe 'Test-MtAnssiAdPkiTemplatePermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights, enrollment rights and reports the most severe level' {
            $ace = @(
                Get-AceFixture -Rid '1200' -Mask 0xF01FF
                Get-AceFixture -Rid '1105' -Mask 0x100 -ObjectType $script:enroll
                Get-AceFixture -Rid '1105' -Mask 0x100
                Get-AceFixture -Rid '1105' -Mask 0x20094
            )
            Use-Ad -Template @((Get-TemplateFixture -Name 'User' -Ace $ace),
                (Get-TemplateFixture -Name 'Old' -Ace @()))

            Test-MtAnssiAdPkiTemplatePermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter {
                $Result -match ('^No principal outside the privileged set can change the 2 ' +
                    'certificate templates')
            }
        }

        It 'fails with severity <Expected> for <Name>' -ForEach @(
            @{ Name = 'a level 1 right on a published template'; Template = 'User'; Mask = 0x40000
                Type = ''; Right = 'WriteDacl'; Expected = 'Critical' }
            @{ Name = 'a level 1 right on an unpublished template'; Template = 'Old'; Mask = 0x40000
                Type = ''; Right = 'WriteDacl'; Expected = 'High' }
            @{ Name = 'a level 2 right on a published template'; Template = 'User'; Mask = 0x8
                Type = ''; Right = 'AllValidatedWrites'; Expected = 'High' }
            @{ Name = 'a write of one attribute'; Template = 'User'; Mask = 0x20; Type = 'NameFlag'
                Right = 'WriteTemplateProperty'; Expected = 'Critical' }
        ) {
            $objectType = ''
            if ($Type) { $objectType = $script:nameFlag }
            $ace = @(Get-AceFixture -Rid '1105' -Mask $Mask -ObjectType $objectType)
            Use-Ad -Template @(Get-TemplateFixture -Name $Template -Ace $ace)

            Test-MtAnssiAdPkiTemplatePermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
            $pattern = "(?s)^1 rights to change certificate templates are held by principals " +
                "outside the privileged set\..*\| $Template \| pki_op \| $Right \| $Expected \|"
            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern $pattern)
        }

        It 'reports an untrusted owner of a published template as Critical' {
            Use-Ad -Template @(Get-TemplateFixture -Name 'User' -Ace @() -Owner '1105')

            Test-MtAnssiAdPkiTemplatePermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            $filter = Get-ResultFilter -Pattern '\| User \| pki_op \| Owner \|'
            Should -Invoke @detail -ParameterFilter $filter
        }

        It 'adds the note about members outside the collected data' {
            Use-Ad -Unresolved @('CN=S-1-5-21-9-9-9-1000,CN=ForeignSecurityPrincipals')

            $null = Test-MtAnssiAdPkiTemplatePermission

            Should -Invoke @detail -ParameterFilter {
                $Result -match '1 member\(s\) outside the collected'
            }
        }
    }

    Context 'data read' {
        It 'reads the templates and the enrollment services of the Configuration partition' {
            Use-Ad

            $null = Test-MtAnssiAdPkiTemplatePermission

            Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($SearchBase -join ';') -eq 'CN=Services,CN=Configuration,DC=contoso,DC=com' -and
                $Scope -eq 'Subtree' -and $Filter -eq '(objectClass=pKICertificateTemplate)' -and
                ($Attribute -join ',') -eq '' -and $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($SearchBase -join ';') -eq 'CN=Services,CN=Configuration,DC=contoso,DC=com' -and
                $Scope -eq 'Subtree' -and $Filter -eq '(objectClass=pKIEnrollmentService)' -and
                ($Attribute -join ',') -eq 'certificateTemplates' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
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
            Should -Invoke Get-MtAnssiAdNamingContextHead -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        }

        It 'trusts the members of the walked groups and the domain groups' {
            $ace = @(
                Get-AceFixture -Rid '1200' -Mask 0x40000
                Get-AceFixture -Rid '512' -Mask 0x40000
            )
            Use-Ad -Template @(Get-TemplateFixture -Name 'User' -Ace $ace)

            Test-MtAnssiAdPkiTemplatePermission | Should -Be $true
        }
    }

    Context 'skips' {
        It 'lets the exception reach the engine when the state cannot be read' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

            { Test-MtAnssiAdPkiTemplatePermission } | Should -Throw

        }

        It 'skips when the domain SID is missing' {
            Use-Ad -DomainSid $null

            $null -eq (Test-MtAnssiAdPkiTemplatePermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
        }

        It 'skips outside the forest root domain: <Name>' -ForEach @(
            @{ Name = 'a child domain'; DnsRoot = 'child.contoso.com'; Forest = 'contoso.com' }
            @{ Name = 'no domain name'; DnsRoot = ''; Forest = 'contoso.com' }
            @{ Name = 'no domain or forest name'; DnsRoot = ''; Forest = '' }
        ) {
            Use-Ad -DnsRoot $DnsRoot -Forest $Forest

            $null -eq (Test-MtAnssiAdPkiTemplatePermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'forest root domain'
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

            { Test-MtAnssiAdPkiTemplatePermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when the permissions of a template cannot be read' {
            Use-Ad -Template @((Get-TemplateFixture -Name 'User' -Ace @()),
                (Get-TemplateFixture -Name 'Old' -Ace $null))

            { Test-MtAnssiAdPkiTemplatePermission } | Should -Throw '*Old* was not read*'

        }
    }
}
