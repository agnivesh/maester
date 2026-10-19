BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-030.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrivilegedGpoPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrivilegedGpoPermission {
        InModuleScope Maester { Test-MtAnssiAdPrivilegedGpoPermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:gpPath = 'f30e3bc1-9ff0-11d1-b603-0000f80367c1'

    function Get-PrincipalFixture {
        param([string] $Name, [string] $Rid)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,OU=Tier0,DC=contoso,DC=com"
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
            [object[]] $Ace = @(),
            [switch] $Unreadable,
            [string] $Note = '',
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
            Users            = @($admin; Get-PrincipalFixture -Name 'gpo_editor' -Rid '1105')
            Computers        = @(Get-PrincipalFixture -Name 'PC1$' -Rid '1106')
            Groups           = @(Get-PrincipalFixture -Name 'Tier0' -Rid '1200')
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @(
                [PSCustomObject]@{ DistinguishedName = $admin.DistinguishedName; Item = $admin }
            )
            Unresolved = @()
            Group      = @('CN=Tier0,OU=Tier0,DC=contoso,DC=com')
        }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $aceList = $Ace
        if ($Unreadable) { $aceList = $null }
        $read = [PSCustomObject]@{
            Gpo  = @([PSCustomObject]@{
                    DistinguishedName = 'cn={1},cn=policies,cn=system,DC=contoso,DC=com'
                    Name = 'Tier0 baseline ({1})'; ObjectClass = @('top', 'groupPolicyContainer')
                    OwnerSid = "$script:domainSid-512"; Ace = $aceList
                })
            Note = $Note
        }
        Mock Get-MtAnssiAdPrivilegedGpo -ModuleName Maester -MockWith ({ $read }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdPrivilegedGpoPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights and keeps the note of the GPO read' {
            Use-Ad -Ace @(Get-AceFixture -Rid '1200' -Mask 0xF01FF) -Note ' NOTE.'

            Test-MtAnssiAdPrivilegedGpoPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No principal outside .* on the 1 GPOs applied to .*\. NOTE\.$'
            }
        }

        It 'fails for <Name>, shown as Critical with the GPO name' -ForEach @(
            @{ Name = 'a file path write'; Mask = 0x20; Path = $true; Right = 'GpoFilePath' }
            @{ Name = 'creating child objects'; Mask = 0x1; Path = $false; Right = 'CreateChild' }
        ) {
            $objectType = ''
            if ($Path) { $objectType = $script:gpPath }
            Use-Ad -Ace @(Get-AceFixture -Rid '1105' -Mask $Mask -ObjectType $objectType) `
                -Note ' NOTE.'

            Test-MtAnssiAdPrivilegedGpoPermission | Should -Be $false

            $pattern = '(?s)^1 dangerous rights on GPOs applied to privileged accounts.* NOTE\..*' +
            '\| Tier0 baseline \(\{1\}\) \| gpo_editor \| ' + $Right + ' \| Critical \|'
            $filter = [scriptblock]::Create("(`$Result -replace '\\', '') -match '$pattern'")
            Should -Invoke @detail -ParameterFilter $filter
        }
    }

    Context 'data read' {
        It 'reads the GPOs applied to the privileged accounts' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedGpoPermission

            Should -Invoke Get-MtAnssiAdPrivilegedGpo -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($Account -join ';') -eq 'CN=admin,OU=Tier0,DC=contoso,DC=com' -and
                $DomainDn -eq 'DC=contoso,DC=com' -and $ProtocolEvidence.ResolvedServer -eq 'dc1'
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
        }
    }

    Context 'skips' {
        It 'lets the exception reach the engine when the state cannot be read' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

            { Test-MtAnssiAdPrivilegedGpoPermission } | Should -Throw

        }

        It 'skips when the domain <Name> is missing' -ForEach @(
            @{ Name = 'SID'; Sid = $null; Dn = 'DC=contoso,DC=com' }
            @{ Name = 'name'; Sid = 'S-1-5-21-1-2-3'; Dn = $null }
        ) {
            Use-Ad -DomainSid $Sid -DomainDn $Dn

            $null -eq (Test-MtAnssiAdPrivilegedGpoPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID or name'
            }
        }

        It 'lets the exception reach the engine when <Command> fails' -ForEach @(
            @{ Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Command = 'Get-MtAnssiAdPrivilegedGpo' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdPrivilegedGpoPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when no GPO applied to a privileged account is visible' {
            Use-Ad
            Mock Get-MtAnssiAdPrivilegedGpo -ModuleName Maester `
                -MockWith { [PSCustomObject]@{ Gpo = @() } }
            $null -eq (Test-MtAnssiAdPrivilegedGpoPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match '^No GPO applied to a privileged account is visible'
            }
        }

        It 'skips when the permissions of a GPO cannot be read' {
            Use-Ad -Unreadable

            $null -eq (Test-MtAnssiAdPrivilegedGpoPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'could not be read'
            }
        }
    }
}
