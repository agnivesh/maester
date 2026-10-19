BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-003.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPkiTemplateSuppliedSubject' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPkiTemplateSuppliedSubject {
        InModuleScope Maester { Test-MtAnssiAdPkiTemplateSuppliedSubject }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $script:services = 'CN=Enrollment Services,CN=Public Key Services,CN=Services'
    $script:ntAuthDn = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services'

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
        param([string] $Rid, [uint32] $Mask = 0x130, [string] $ObjectType = $script:enroll)
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = "$script:domainSid-$Rid"
        }
    }

    function Get-TemplateFixture {
        param(
            [string] $Name = 'ESC1',
            [AllowNull()] [object[]] $Ace = @(Get-AceFixture -Rid '1105'),
            $NameFlag = 1,
            $Eku = @('1.3.6.1.5.5.7.3.2'),
            $EnrollmentFlag = 0
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=Certificate Templates,CN=Public Key Services"
            Name              = $Name
            ObjectClass       = @('top', 'pKICertificateTemplate')
            OwnerSid          = "$script:domainSid-512"
            Ace               = $Ace
            Attribute         = [ordered]@{
                'msPKI-Certificate-Name-Flag' = $NameFlag
                'pKIExtendedKeyUsage'         = $Eku
                'msPKI-Enrollment-Flag'       = $EnrollmentFlag
                'msPKI-RA-Signature'          = 0
            }
        }
    }

    function Use-Ad {
        param(
            [object[]] $Template = @(Get-TemplateFixture),
            [string[]] $Published = @('ESC1'),
            [switch] $CaNotTrusted,
            [switch] $NoNtAuth,
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
            Users            = @($admin; Get-PrincipalFixture -Name 'alice' -Rid '1105')
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
        $script:caList = @([PSCustomObject]@{
                DistinguishedName = "CN=Contoso CA,$script:services"; Name = 'Contoso CA'
                ObjectClass = @('top', 'pKIEnrollmentService'); OwnerSid = "$script:domainSid-512"
                Ace = @(); Attribute = [ordered]@{ certificateTemplates = $Published }
            })
        $caBytes = [byte[]](1, 2, 3)
        $ntAuthBytes = $caBytes
        if ($CaNotTrusted) { $ntAuthBytes = [byte[]](9, 9, 9) }
        $script:certificates = @(
            [PSCustomObject]@{
                DistinguishedName = "CN=Contoso CA,$script:services"; Name = 'Contoso CA'
                Certificate = @(,$caBytes)
            }
        )
        if (-not $NoNtAuth) {
            $script:certificates += [PSCustomObject]@{
                DistinguishedName = $script:ntAuthDn; Name = 'NTAuthCertificates'
                Certificate = @(,$ntAuthBytes)
            }
        }
        Mock Get-MtAnssiAdSearchSecurity -ModuleName Maester -MockWith {
            if ($Filter -eq '(objectClass=pKIEnrollmentService)') { return $script:caList }
            $script:templates
        }
        Mock Get-MtAnssiAdCaCertificate -ModuleName Maester -MockWith { $script:certificates }
    }

    function Get-ResultFilter {
        param([string] $Pattern)
        [scriptblock]::Create("(`$Result -replace '\\', '') -match '$Pattern'")
    }
}

Describe 'Test-MtAnssiAdPkiTemplateSuppliedSubject' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when only privileged principals can enroll' {
            Use-Ad -Template @(
                Get-TemplateFixture -Ace @(Get-AceFixture -Rid '1200'; Get-AceFixture -Rid '512')
            )

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    '^No principal outside the privileged set can enroll in the 1 certificate ' +
                    'templates'))
        }

        It 'fails with level 1 and says the attack works today when a trusted CA publishes it' {
            Use-Ad

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    '(?s)^1 rights to enroll .*A CA trusted for logon publishes these ' +
                    'templates, so the attack works today: ESC1\..*' +
                    '\| ESC1 \| alice \| Enroll \| Critical \| No \|'))
        }

        It 'leaves the severity to the configuration' -ForEach @(
            @{ Verdict = $false; Setup = { Use-Ad } }
            @{ Verdict = $true; Setup = { Use-Ad -Template @() } }
        ) {
            & $Setup
            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $Verdict

            Should -Invoke Add-MtTestResultDetail -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $PesterBoundParameters.ContainsKey('Result') }
            Should -Invoke Add-MtTestResultDetail -ModuleName Maester -Times 0 -Exactly `
                -ParameterFilter { $PesterBoundParameters.ContainsKey('Severity') }
        }

        It 'fails with level 1 and no publication note when the publishing CA is not trusted' {
            Use-Ad -CaNotTrusted

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    '(?s)^1 rights to enroll (?!.*attack works today).*' +
                    '\| ESC1 \| alice \| Enroll \| Critical \|'))
        }

        It 'fails with level 1 when no CA publishes the template' {
            Use-Ad -Published @()

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    '(?s)^1 rights to enroll (?!.*attack works today).*' +
                    '\| ESC1 \| alice \| Enroll \| Critical \|'))
        }

        It 'reports every template at level 1 and names only the published ones as live' {
            Use-Ad -Published @('ESC1') -Template @(
                Get-TemplateFixture -Name 'ESC1'
                Get-TemplateFixture -Name 'Hidden'
            )

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    '(?s)^2 rights .*works today: ESC1\..*' +
                    '\| ESC1 \| alice \| Enroll \| Critical .*' +
                    '\| Hidden \| alice \| Enroll \| Critical '))
        }

        It 'does not judge a template that does not let the requester name the certificate' {
            Use-Ad -Template @(Get-TemplateFixture -NameFlag 0x42000000)

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    'can enroll in the 0 certificate templates'))
        }

        It 'does not judge a template whose certificate cannot be used to log on' {
            Use-Ad -Template @(Get-TemplateFixture -Eku @('1.3.6.1.5.5.7.3.1'))

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $true
        }

        It 'fails on a template with no usage restriction' {
            Use-Ad -Template @(Get-TemplateFixture -Eku $null)

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $false
        }

        It 'does not report enrollment that only autoenrollment or reading allows' {
            Use-Ad -Template @(
                Get-TemplateFixture -Ace @(
                    Get-AceFixture -Rid '1105' -Mask 0x100 `
                        -ObjectType 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
                    Get-AceFixture -Rid '1105' -Mask 0x20094 -ObjectType ''
                )
            )

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $true
        }

        It 'notes the templates that a manager has to approve' {
            Use-Ad -Template @(Get-TemplateFixture -EnrollmentFlag 2)

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    'manager approval or authorized signatures.*ESC1'))
        }

        It 'adds no approval note when no template needs one' {
            Use-Ad

            $null = Test-MtAnssiAdPkiTemplateSuppliedSubject

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch 'manager approval'
            }
        }
    }

    Context 'data read' {
        It 'reads the templates with the attributes the test judges' {
            Use-Ad

            $null = Test-MtAnssiAdPkiTemplateSuppliedSubject

            Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($SearchBase -join ';') -eq 'CN=Services,CN=Configuration,DC=contoso,DC=com' -and
                $Scope -eq 'Subtree' -and $Filter -eq '(objectClass=pKICertificateTemplate)' -and
                $Attribute -contains 'msPKI-Certificate-Name-Flag' -and
                $Attribute -contains 'pKIExtendedKeyUsage' -and
                $Attribute -contains 'msPKI-Enrollment-Flag' -and
                $Attribute -contains 'msPKI-RA-Signature' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }

        It 'reads the enrollment services and the certificates of the Services container' {
            Use-Ad

            $null = Test-MtAnssiAdPkiTemplateSuppliedSubject

            Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $Filter -eq '(objectClass=pKIEnrollmentService)' -and
                $Attribute -contains 'certificateTemplates' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdCaCertificate -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $SearchBase -eq 'CN=Services,CN=Configuration,DC=contoso,DC=com' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
        }

        It 'works out the privileged set from the collected state' {
            Use-Ad

            $null = Test-MtAnssiAdPkiTemplateSuppliedSubject

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and $ProtocolEvidence.ResolvedServer -eq 'dc1' -and
                @($User).Count -eq 2 -and @($Computer).Count -eq 1 -and @($Group).Count -eq 1
            }
        }

        It 'adds the note about members outside the collected data' {
            Use-Ad -Unresolved @('CN=S-1-5-21-9-9-9-1000,CN=ForeignSecurityPrincipals')

            $null = Test-MtAnssiAdPkiTemplateSuppliedSubject

            Should -Invoke @detail -ParameterFilter {
                $Result -match '1 member\(s\) outside the collected'
            }
        }

        It 'adds the note to a passing result too' {
            Use-Ad -Template @(Get-TemplateFixture -Ace @()) `
                -Unresolved @('CN=S-1-5-21-9-9-9-1000,CN=ForeignSecurityPrincipals')

            $null = Test-MtAnssiAdPkiTemplateSuppliedSubject

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No principal .* 1 member\(s\) outside the collected'
            }
        }
    }

    Context 'skips' {
        It 'lets the exception reach the engine when the state cannot be read' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'state failed' }

            { Test-MtAnssiAdPkiTemplateSuppliedSubject } | Should -Throw '*state failed*'

        }

        It 'skips when the domain SID is missing' {
            Use-Ad -DomainSid $null

            $null -eq (Test-MtAnssiAdPkiTemplateSuppliedSubject) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
        }

        It 'skips outside the forest root domain' -ForEach @(
            @{ DnsRoot = 'child.contoso.com'; Forest = 'contoso.com' }
            @{ DnsRoot = $null; Forest = 'contoso.com' }
            @{ DnsRoot = $null; Forest = $null }
        ) {
            Use-Ad -DnsRoot $DnsRoot -Forest $Forest

            $null -eq (Test-MtAnssiAdPkiTemplateSuppliedSubject) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'forest root domain'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
        }

        It 'lets the exception reach the engine when <Command> fails' -ForEach @(
            @{ Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Command = 'Get-MtAnssiAdNamingContextHead' }
            @{ Command = 'Get-MtAnssiAdSearchSecurity' }
            @{ Command = 'Get-MtAnssiAdCaCertificate' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdPkiTemplateSuppliedSubject } | Should -Throw '*LDAP failed*'

        }

        It 'still reports level 1 when the forest has no NTAuth store, so no CA is trusted' {
            Use-Ad -NoNtAuth

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    '(?s)^1 rights to enroll (?!.*attack works today).*\| Critical \|'))
        }

        It 'lets the exception reach the engine when the permissions of a template cannot be read' {
            Use-Ad -Template @(Get-TemplateFixture -Ace $null)

            { Test-MtAnssiAdPkiTemplateSuppliedSubject } | Should -Throw '*was not read*'

        }

        It 'does not need the permissions of a template that it does not judge' {
            Use-Ad -Template @(
                Get-TemplateFixture -Name 'ESC1' -Ace @(Get-AceFixture -Rid '1200')
                Get-TemplateFixture -Name 'Other' -NameFlag 0 -Ace $null
            )

            Test-MtAnssiAdPkiTemplateSuppliedSubject | Should -Be $true
        }
    }
}
