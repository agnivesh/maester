BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-022.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdAdminSdHolderPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdAdminSdHolderPermission {
        InModuleScope Maester { Test-MtAnssiAdAdminSdHolderPermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:spn = 'f3a64788-5306-11d1-a9c5-0000f80367c1'

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
        if (-not $Sid) { $Sid = "$script:domainSid-$Rid" }
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = $Sid
        }
    }

    function Use-Ad {
        param(
            [object[]] $Ace = @(),
            [string] $Owner = "$script:domainSid-512",
            [switch] $Unreadable,
            [object[]] $Unresolved = @(),
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
            Users            = @($admin; Get-PrincipalFixture -Name 'svc_a' -Rid '1105')
            Computers        = @(Get-PrincipalFixture -Name 'PC1$' -Rid '1106')
            Groups           = @(
                Get-PrincipalFixture -Name 'Tier0' -Rid '1200'
                Get-PrincipalFixture -Name 'Helpdesk' -Rid '1201'
            )
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
        $aceList = $Ace
        if ($Unreadable) { $aceList = $null }
        $target = [PSCustomObject]@{
            DistinguishedName = "CN=AdminSDHolder,CN=System,$DomainDn"
            Name              = 'AdminSDHolder'
            ObjectClass       = @('top', 'container')
            OwnerSid          = $Owner
            Ace               = $aceList
        }
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith ({ $target }.GetNewClosure())
    }

    function Get-Severity {
        param([string] $Expected)
        [scriptblock]::Create("`$Severity -eq '$Expected'")
    }
}

Describe 'Test-MtAnssiAdAdminSdHolderPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights and reports the most severe level' {
            Use-Ad -Ace @(
                Get-AceFixture -Rid '512' -Mask 0xF01FF
                Get-AceFixture -Rid '1100' -Mask 0x40000
                Get-AceFixture -Rid '1200' -Mask 0x80000
                Get-AceFixture -Sid 'S-1-5-11' -Mask 0x20094
            )

            Test-MtAnssiAdAdminSdHolderPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No principal outside the privileged set holds a dangerous right'
            }
        }

        It 'fails with severity <Expected> for <Name>' -ForEach @(
            @{ Name = 'a level 1 right'; Mask = 0x40000; Type = ''; Expected = 'Critical' }
            @{
                Name = 'a level 2 right'; Mask = 0x20; Type = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
                Expected = 'High'
            }
        ) {
            Use-Ad -Ace @(Get-AceFixture -Rid '1201' -Mask $Mask -ObjectType $Type)

            Test-MtAnssiAdAdminSdHolderPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 dangerous rights on AdminSDHolder are held by principals'
            }
        }

        It 'reports the most severe level of several rights' {
            Use-Ad -Ace @(
                Get-AceFixture -Rid '1201' -Mask 0x20 -ObjectType $script:spn
                Get-AceFixture -Rid '1105' -Mask 0x80000
            )

            Test-MtAnssiAdAdminSdHolderPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
        }

        It 'fails for an untrusted owner' {
            Use-Ad -Owner "$script:domainSid-1105"

            Test-MtAnssiAdAdminSdHolderPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                ($Result -replace '\\', '') -match
                '\| AdminSDHolder \| svc_a \| Owner \| Critical \| No \|'
            }
        }

        It 'judges the template as the users, computers and groups it is copied to' {
            Use-Ad -Ace @(
                Get-AceFixture -Rid '1201' -Mask 0x8
                Get-AceFixture -Rid '1105' -Mask 0x1
            )

            Test-MtAnssiAdAdminSdHolderPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 dangerous rights' -and
                $Result -match '\| Helpdesk \| WriteMember \| Critical \|'
            }
        }

        It 'lists the rights worst first with escaped trustee names' {
            Use-Ad -Ace @(
                Get-AceFixture -Rid '1201' -Mask 0x20 -ObjectType $script:spn
                Get-AceFixture -Rid '1105' -Mask 0x40000
                Get-AceFixture -Sid 'S-1-5-21-9-9-9-1300' -Mask 0x80000
            )

            $null = Test-MtAnssiAdAdminSdHolderPermission

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'svc\\_a' -and
                $Result -match ('(?s)S-1-5-21-9-9-9-1300 \| WriteOwner.*svc\\_a \| WriteDacl.*' +
                    'Helpdesk \| WriteSpn \| High')
            }
        }

        It 'adds the note about members not checked to a <Name> result' -ForEach @(
            @{ Name = 'passing'; Mask = 0x20094 }
            @{ Name = 'failing'; Mask = 0x40000 }
        ) {
            $missing = [PSCustomObject]@{ DistinguishedName = 'CN=x'; Group = @('Domain Admins') }
            Use-Ad -Unresolved @($missing) -Ace @(Get-AceFixture -Rid '1201' -Mask $Mask)

            $null = Test-MtAnssiAdAdminSdHolderPermission

            Should -Invoke @detail -ParameterFilter { $Result -match 'not checked' }
        }
    }

    Context 'data read' {
        It 'reads the Domain, Users, Computers and Groups categories' {
            Use-Ad

            $null = Test-MtAnssiAdAdminSdHolderPermission

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
        }

        It 'lists the privileged accounts and reads AdminSDHolder of the domain' {
            Use-Ad

            $null = Test-MtAnssiAdAdminSdHolderPermission

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'admin' -and
                @($Computer)[0].Name -eq 'PC1$' -and @($Group)[0].Name -eq 'Tier0' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                (@($DistinguishedName) -join ';') -eq
                'CN=AdminSDHolder,CN=System,DC=contoso,DC=com' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }
    }

    Context 'skips' {
        It 'lets the exception reach the engine when the state cannot be read' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

            { Test-MtAnssiAdAdminSdHolderPermission } | Should -Throw

        }

        It 'skips when the domain <Name> is missing' -ForEach @(
            @{ Name = 'SID'; Sid = $null; Dn = 'DC=contoso,DC=com' }
            @{ Name = 'name'; Sid = 'S-1-5-21-1-2-3'; Dn = $null }
        ) {
            Use-Ad -DomainSid $Sid -DomainDn $Dn

            $null -eq (Test-MtAnssiAdAdminSdHolderPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID or name'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
        }

        It 'lets the exception reach the engine when <Name> fails' -ForEach @(
            @{ Name = 'the privileged list'; Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Name = 'the AdminSDHolder read'; Command = 'Get-MtAnssiAdObjectSecurity' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdAdminSdHolderPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when the permissions of AdminSDHolder cannot be read' {
            Use-Ad -Unreadable

            $null -eq (Test-MtAnssiAdAdminSdHolderPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'could not be read'
            }
        }
    }
}
