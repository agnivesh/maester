BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-033.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrivilegedMemberPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrivilegedMemberPermission {
        InModuleScope Maester { Test-MtAnssiAdPrivilegedMemberPermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:reset = '00299570-246d-11d0-a768-00aa006e0529'
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
        param([string] $Rid, [uint32] $Mask, [string] $ObjectType = '')
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = "$script:domainSid-$Rid"
        }
    }

    function Use-Ad {
        param(
            [hashtable] $Ace = @{},
            [string[]] $Unreadable = @(),
            [AllowNull()] [string] $DomainSid = $script:domainSid
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $admin = Get-PrincipalFixture -Name 'admin' -Rid '1100'
        $dc = Get-PrincipalFixture -Name 'DC1' -Rid '1000'
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{ DomainSID = $sidValue }
            Users            = @($admin; Get-PrincipalFixture -Name 'helpdesk_op' -Rid '1105')
            Computers        = @($dc)
            Groups           = @(
                Get-PrincipalFixture -Name 'Tier0' -Rid '1200'
                Get-PrincipalFixture -Name 'Helpdesk' -Rid '1201'
            )
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @(
                [PSCustomObject]@{ DistinguishedName = $admin.DistinguishedName; Item = $admin }
                [PSCustomObject]@{ DistinguishedName = $dc.DistinguishedName; Item = $dc }
            )
            Unresolved = @()
            Group      = @('CN=Domain Admins,DC=contoso,DC=com', 'CN=Tier0,DC=contoso,DC=com')
        }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $script:aceByName = $Ace
        $script:unreadableName = $Unreadable
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith {
            foreach ($dn in $DistinguishedName) {
                $name = ($dn -split ',')[0] -replace '^CN=', ''
                $aceList = @($script:aceByName[$name])
                if ($name -in $script:unreadableName) { $aceList = $null }
                [PSCustomObject]@{
                    DistinguishedName = $dn; Name = $name; ObjectClass = @('top', 'user')
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

Describe 'Test-MtAnssiAdPrivilegedMemberPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights and reports the most severe level' {
            Use-Ad -Ace @{
                admin = @(Get-AceFixture -Rid '1200' -Mask 0x100 -ObjectType $script:reset)
                DC1   = @(Get-AceFixture -Rid '1000' -Mask 0x20 -ObjectType $script:spn)
            }

            Test-MtAnssiAdPrivilegedMemberPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No principal outside .* on the 4 privileged accounts and groups'
            }
        }

        It 'fails with severity <Expected> for <Name>' -ForEach @(
            @{ Name = 'a password reset'; Target = 'admin'; Spn = $false; Expected = 'Critical' }
            @{ Name = 'an SPN write'; Target = 'DC1'; Spn = $true; Expected = 'High' }
        ) {
            $ace = Get-AceFixture -Rid '1105' -Mask 0x100 -ObjectType $script:reset
            if ($Spn) { $ace = Get-AceFixture -Rid '1105' -Mask 0x20 -ObjectType $script:spn }
            Use-Ad -Ace @{ $Target = @($ace) }

            Test-MtAnssiAdPrivilegedMemberPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 dangerous rights on privileged accounts and groups' -and
                ($Result -replace '\\', '') -match '\| helpdesk_op \|'
            }
        }

        It 'reports rights on the walked groups and the most severe level of several' {
            Use-Ad -Ace @{
                Tier0 = @(Get-AceFixture -Rid '1201' -Mask 0x40000)
                DC1   = @(Get-AceFixture -Rid '1201' -Mask 0x20 -ObjectType $script:spn)
            }

            Test-MtAnssiAdPrivilegedMemberPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter {
                $Result -match '^2 dangerous rights' -and
                $Result -match '\| Tier0 \| Helpdesk \| WriteDacl \|'
            }
        }
    }

    Context 'data read' {
        It 'reads every privileged account and walked group' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedMemberPermission

            Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($DistinguishedName -join ';') -eq ('CN=admin,DC=contoso,DC=com;' +
                    'CN=DC1,DC=contoso,DC=com;' +
                    'CN=Domain Admins,DC=contoso,DC=com;CN=Tier0,DC=contoso,DC=com') -and
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
                @($Computer)[0].Name -eq 'DC1' -and @($Group)[0].Name -eq 'Tier0' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }
    }

    Context 'skips' {
        It 'lets the exception reach the engine when the state cannot be read' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

            { Test-MtAnssiAdPrivilegedMemberPermission } | Should -Throw

        }

        It 'skips when the domain SID is missing' {
            Use-Ad -DomainSid $null

            $null -eq (Test-MtAnssiAdPrivilegedMemberPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'lets the exception reach the engine when <Command> fails' -ForEach @(
            @{ Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Command = 'Get-MtAnssiAdObjectSecurity' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdPrivilegedMemberPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when no privileged account or group is visible' {
            Use-Ad
            Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith { @() }
            $null -eq (Test-MtAnssiAdPrivilegedMemberPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match '^No privileged account or group is visible'
            }
        }

        It 'skips when the permissions of an object cannot be read' {
            Use-Ad -Unreadable @('Tier0')

            $null -eq (Test-MtAnssiAdPrivilegedMemberPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match
                '^No privileged account or group is visible, or the permissions of 1 of them'
            }
        }
    }
}
