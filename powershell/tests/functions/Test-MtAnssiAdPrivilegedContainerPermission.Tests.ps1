BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-049.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrivilegedContainerPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrivilegedContainerPermission {
        InModuleScope Maester { Test-MtAnssiAdPrivilegedContainerPermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:gpLink = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'

    function Get-PrincipalFixture {
        param([string] $Name, [string] $Rid, [string] $Path = 'DC=contoso,DC=com')
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,$Path"
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
            [AllowNull()] [string] $DomainSid = $script:domainSid,
            [AllowNull()] [string] $DomainDn = 'DC=contoso,DC=com'
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $admin = Get-PrincipalFixture -Name 'admin' -Rid '1100' `
            -Path 'OU=Admins,OU=Tier0,DC=contoso,DC=com'
        $dc = Get-PrincipalFixture -Name 'DC1' -Rid '1000' `
            -Path 'OU=Domain Controllers,DC=contoso,DC=com'
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID = $sidValue; DistinguishedName = $DomainDn
            }
            Users            = @($admin; Get-PrincipalFixture -Name 'helpdesk_op' -Rid '1105')
            Computers        = @($dc)
            Groups           = @(Get-PrincipalFixture -Name 'Tier0' -Rid '1200')
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @(
                [PSCustomObject]@{ DistinguishedName = $admin.DistinguishedName; Item = $admin }
                [PSCustomObject]@{ DistinguishedName = $dc.DistinguishedName; Item = $dc }
            )
            Unresolved = @()
            Group      = @('CN=Tier0,DC=contoso,DC=com')
        }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $script:aceByName = $Ace
        $script:unreadableName = $Unreadable
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith {
            foreach ($dn in $DistinguishedName) {
                $name = ($dn -split ',')[0] -replace '^(OU|CN)=', ''
                $aceList = @($script:aceByName[$name])
                if ($name -in $script:unreadableName) { $aceList = $null }
                [PSCustomObject]@{
                    DistinguishedName = $dn; Name = $name
                    ObjectClass = @('top', 'organizationalUnit'); OwnerSid = "$script:domainSid-512"
                    Ace = $aceList; Attribute = [ordered]@{ gPLink = ''; gPOptions = $null }
                }
            }
        }
    }
}

Describe 'Test-MtAnssiAdPrivilegedContainerPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights' {
            $ace = Get-AceFixture -Rid '1200' -Mask 0x20 -ObjectType $script:gpLink
            Use-Ad -Ace @{ Admins = @($ace) }

            Test-MtAnssiAdPrivilegedContainerPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No principal outside .* on the 3 containers of privileged accounts'
            }
        }

        It 'fails for a right to link GPOs, shown as High with the container DN below the domain' {
            $ace = Get-AceFixture -Rid '1105' -Mask 0x20 -ObjectType $script:gpLink
            Use-Ad -Ace @{ Tier0 = @($ace) }

            Test-MtAnssiAdPrivilegedContainerPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 dangerous rights on containers of privileged accounts' -and
                ($Result -replace '\\', '') -match
                '\| OU=Tier0 \| helpdesk_op \| GpLink \| High \|'
            }
        }
    }

    Context 'data read' {
        It 'reads the containers above the privileged accounts with their group policy attributes' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedContainerPermission

            Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($DistinguishedName -join ';') -eq ('OU=Admins,OU=Tier0,DC=contoso,DC=com;' +
                    'OU=Tier0,DC=contoso,DC=com;OU=Domain Controllers,DC=contoso,DC=com') -and
                ($Attribute -join ',') -eq 'gPLink,gPOptions' -and
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

            { Test-MtAnssiAdPrivilegedContainerPermission } | Should -Throw

        }

        It 'skips when the domain <Name> is missing' -ForEach @(
            @{ Name = 'SID'; Sid = $null; Dn = 'DC=contoso,DC=com' }
            @{ Name = 'name'; Sid = 'S-1-5-21-1-2-3'; Dn = $null }
        ) {
            Use-Ad -DomainSid $Sid -DomainDn $Dn

            $null -eq (Test-MtAnssiAdPrivilegedContainerPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID or name'
            }
        }

        It 'lets the exception reach the engine when <Command> fails' -ForEach @(
            @{ Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Command = 'Get-MtAnssiAdObjectSecurity' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdPrivilegedContainerPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when no container of privileged accounts is visible' {
            Use-Ad
            Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith { @() }
            $null -eq (Test-MtAnssiAdPrivilegedContainerPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match '^No container of privileged accounts is visible'
            }
        }

        It 'skips when the permissions of a container cannot be read' {
            Use-Ad -Unreadable @('Tier0')

            $null -eq (Test-MtAnssiAdPrivilegedContainerPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'could not be read'
            }
        }
    }
}
