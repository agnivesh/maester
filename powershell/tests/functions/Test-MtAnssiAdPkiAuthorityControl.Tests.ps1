BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-001.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPkiAuthorityControl' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPkiAuthorityControl {
        InModuleScope Maester { Test-MtAnssiAdPkiAuthorityControl }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $script:caCertificate = 'bf967932-0de6-11d0-a285-00aa003049e2'
    $script:other = 'bf967950-0de6-11d0-a285-00aa003049e2'
    $script:base = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'

    function Get-PrincipalFixture {
        param([string] $Name, [string] $Rid, [string] $HostName = '')
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Name              = $Name
            SamAccountName    = $Name
            DnsHostName       = $HostName
            Sid               = [PSCustomObject]@{ Value = "$script:domainSid-$Rid" }
        }
    }

    function Get-AceFixture {
        param([string] $Sid, [uint32] $Mask, [string] $ObjectType = '')
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = $Sid
        }
    }

    function Get-UserAce {
        param([uint32] $Mask, [string] $ObjectType = '')
        Get-AceFixture -Sid "$script:domainSid-1105" -Mask $Mask -ObjectType $ObjectType
    }

    function Get-DefaultAce {
        @(
            Get-AceFixture -Sid 'S-1-5-11' -Mask 0x20094
            Get-AceFixture -Sid 'S-1-1-0' -Mask 0x20094
            Get-AceFixture -Sid 'S-1-5-11' -Mask 0x100 -ObjectType $script:enroll
            Get-AceFixture -Sid 'S-1-5-18' -Mask 0xF01FF
            Get-AceFixture -Sid 'S-1-5-32-544' -Mask 0xF01FF
            Get-AceFixture -Sid "$script:domainSid-512" -Mask 0xF01FF
            Get-AceFixture -Sid "$script:domainSid-519" -Mask 0xF01FF
            Get-AceFixture -Sid "$script:domainSid-517" -Mask 0xF01FF
            Get-AceFixture -Sid "$script:domainSid-1106" -Mask 0xF01FF
        )
    }

    function Get-ObjectFixture {
        param(
            [string] $Name, [string] $Class = 'container', [AllowNull()] [object[]] $Ace,
            [string] $Owner = "$script:domainSid-519", [string] $HostName = $null
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,$script:base"
            Name              = $Name
            ObjectClass       = @('top', $Class)
            OwnerSid          = $Owner
            Ace               = $Ace
            Attribute         = [ordered]@{ dNSHostName = $HostName }
        }
    }

    function Use-Ad {
        param(
            [object[]] $Object = @(
                Get-ObjectFixture -Name 'Public Key Services' -Ace (Get-DefaultAce)
                Get-ObjectFixture -Name 'CA1' -Class 'pKIEnrollmentService' -Ace (Get-DefaultAce) `
                    -HostName 'ca1.contoso.com'
            ),
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
            Computers        = @(
                Get-PrincipalFixture -Name 'CA1$' -Rid '1106' -HostName 'ca1.contoso.com'
                Get-PrincipalFixture -Name 'PC2$' -Rid '1107' -HostName 'pc2.contoso.com'
            )
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
        $script:objects = $Object
        Mock Get-MtAnssiAdSearchSecurity -ModuleName Maester -MockWith { $script:objects }
    }

    function Get-ResultFilter {
        param([string] $Pattern)
        [scriptblock]::Create("(`$Result -replace '\\', '') -match '$Pattern'")
    }

    function Use-OneObject {
        param([object[]] $Ace, [string] $Owner = "$script:domainSid-519")
        $object = Get-ObjectFixture -Name 'Certification Authorities' -Ace $Ace -Owner $Owner
        Use-Ad -Object @($object)
    }
}

Describe 'Test-MtAnssiAdPkiAuthorityControl' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes for a default CA installation' {
            Use-Ad

            Test-MtAnssiAdPkiAuthorityControl | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    '^No principal outside the privileged set holds a dangerous right on the 2 ' +
                    'certificate containers and CA objects'))
        }

        It 'fails for <Name> held by an untrusted user' -ForEach @(
            @{ Name = 'full control'; Mask = 0x10000000; Type = ''; Right = 'GenericAll' }
            @{ Name = 'full control as a mask'; Mask = 0xF01FF; Type = ''; Right = 'GenericAll' }
            @{ Name = 'the right to change ACLs'; Mask = 0x40000; Type = ''; Right = 'WriteDacl' }
            @{ Name = 'the owner right'; Mask = 0x80000; Type = ''; Right = 'WriteOwner' }
            @{ Name = 'generic write'; Mask = 0x40000000; Type = ''; Right = 'GenericWrite' }
            @{ Name = 'writing all properties'; Mask = 0x20; Type = ''; Right = 'GenericWrite' }
            @{
                Name = 'writing the list of CAs'; Mask = 0x20
                Type = 'bf967932-0de6-11d0-a285-00aa003049e2'; Right = 'WriteCaCertificate'
            }
            @{ Name = 'adding a child object'; Mask = 0x1; Type = ''; Right = 'CreateChild' }
        ) {
            Use-OneObject -Ace @(Get-UserAce -Mask $Mask -ObjectType $Type)

            Test-MtAnssiAdPkiAuthorityControl | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    "(?s)^1 dangerous rights on the certificate containers.*" +
                    "\| Certification Authorities \| alice \| $Right \| Critical \| No \|"))
        }

        It 'does not report <Name>' -ForEach @(
            @{ Name = 'reading'; Mask = 0x20094; Type = '' }
            @{ Name = 'enrolling'; Mask = 0x100; Type = '0e10c968-78fb-11d2-90d4-00c04f79dc55' }
            @{
                Name = 'another attribute'; Mask = 0x20
                Type = 'bf967950-0de6-11d0-a285-00aa003049e2'
            }
            @{ Name = 'deleting'; Mask = 0x10000; Type = '' }
            @{ Name = 'listing children'; Mask = 0x4; Type = '' }
        ) {
            Use-OneObject -Ace @(Get-UserAce -Mask $Mask -ObjectType $Type)

            Test-MtAnssiAdPkiAuthorityControl | Should -Be $true
        }

        It 'expects the groups that were walked to find the privileged accounts' {
            Use-OneObject -Ace @(
                Get-AceFixture -Sid "$script:domainSid-1200" -Mask 0xF01FF
            )

            Test-MtAnssiAdPkiAuthorityControl | Should -Be $true
        }

        It 'fails for an owner outside the privileged set' {
            Use-OneObject -Ace @() -Owner "$script:domainSid-1105"

            Test-MtAnssiAdPkiAuthorityControl | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-ResultFilter -Pattern (
                    '\| Certification Authorities \| alice \| Owner \| Critical \|'))
        }

        It 'expects Cert Publishers and the CA server, no other computer or domain' -ForEach @(
            @{ Sid = 'S-1-5-21-1-2-3-517'; Expected = $true }
            @{ Sid = 'S-1-5-21-1-2-3-1106'; Expected = $true }
            @{ Sid = 'S-1-5-21-1-2-3-1107'; Expected = $false }
            @{ Sid = 'S-1-5-21-9-9-9-517'; Expected = $false }
            @{ Sid = 'S-1-5-21-9-9-9-1106'; Expected = $false }
            @{ Sid = 'S-1-5-21-1-2-3-518'; Expected = $true }
        ) {
            $ace = @(Get-AceFixture -Sid $Sid -Mask 0xF01FF)
            Use-Ad -Object @(
                Get-ObjectFixture -Name 'CA1' -Class 'pKIEnrollmentService' -Ace $ace `
                    -HostName 'ca1.contoso.com'
            )

            Test-MtAnssiAdPkiAuthorityControl | Should -Be $Expected
        }

        It 'expects a CA server only for an enrollment service that names it' {
            $ace = @(Get-AceFixture -Sid "$script:domainSid-1106" -Mask 0xF01FF)
            Use-Ad -Object @(
                Get-ObjectFixture -Name 'CA1' -Class 'pKIEnrollmentService' -Ace @() `
                    -HostName 'pc2.contoso.com'
                Get-ObjectFixture -Name 'Container' -Ace $ace
            )

            Test-MtAnssiAdPkiAuthorityControl | Should -Be $false
        }

        It 'reports each right on each object' {
            Use-Ad -Object @(
                Get-ObjectFixture -Name 'A' -Ace @(
                    Get-AceFixture -Sid "$script:domainSid-1105" -Mask 0x40000
                    Get-AceFixture -Sid "$script:domainSid-1105" -Mask 0x1
                )
                Get-ObjectFixture -Name 'B' -Ace @(
                    Get-AceFixture -Sid "$script:domainSid-1107" -Mask 0x80000)
            )

            Test-MtAnssiAdPkiAuthorityControl | Should -Be $false

            Should -Invoke @detail -ParameterFilter (
                Get-ResultFilter -Pattern '^3 dangerous rights')
        }

        It 'adds the note about members outside the collected data' {
            Use-Ad -Unresolved @('CN=S-1-5-21-9-9-9-1000,CN=ForeignSecurityPrincipals')

            $null = Test-MtAnssiAdPkiAuthorityControl

            Should -Invoke @detail -ParameterFilter {
                $Result -match '1 member\(s\) outside the collected'
            }
        }

        It 'is skipped when no PKI object is visible, not passed' {
            Use-Ad -Object @()

            $null -eq (Test-MtAnssiAdPkiAuthorityControl) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match '^No PKI container is visible'
            }
        }
    }

    Context 'data read' {
        It 'reads the owner and permissions of the PKI objects below Public Key Services' {
            Use-Ad

            $null = Test-MtAnssiAdPkiAuthorityControl

            Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($SearchBase -join ';') -eq $script:base -and $Scope -eq 'Subtree' -and
                $Filter -eq ('(|(objectClass=container)(objectClass=certificationAuthority)' +
                    '(objectClass=pKIEnrollmentService)(objectClass=cRLDistributionPoint)' +
                    '(objectClass=msPKI-PrivateKeyRecoveryAgent))') -and
                $Attribute -contains 'dNSHostName' -and
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

            $null = Test-MtAnssiAdPkiAuthorityControl

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and $ProtocolEvidence.ResolvedServer -eq 'dc1' -and
                @($User).Count -eq 2 -and @($Computer).Count -eq 2 -and @($Group).Count -eq 1
            }
        }
    }

    Context 'skips' {
        It 'lets the exception reach the engine when the state cannot be read' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'state failed' }

            { Test-MtAnssiAdPkiAuthorityControl } | Should -Throw '*state failed*'

        }

        It 'skips when the domain SID is missing' {
            Use-Ad -DomainSid $null

            $null -eq (Test-MtAnssiAdPkiAuthorityControl) | Should -Be $true

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

            $null -eq (Test-MtAnssiAdPkiAuthorityControl) | Should -Be $true

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

            { Test-MtAnssiAdPkiAuthorityControl } | Should -Throw '*LDAP failed*'

        }

        It 'lets the exception reach the engine when the permissions of an object cannot be read' {
            Use-Ad -Object @(Get-ObjectFixture -Name 'Unread' -Ace $null)

            { Test-MtAnssiAdPkiAuthorityControl } | Should -Throw '*was not read*'

        }
    }
}
