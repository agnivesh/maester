BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-023.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDcPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDcPermission {
        InModuleScope Maester { Test-MtAnssiAdDcPermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:spn = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    $script:managedBy = '0296c120-40da-11d1-a9c0-0000f80367c1'

    function Get-PrincipalFixture {
        param([string] $Name, [string] $Rid, [AllowNull()] [object] $PrimaryGroupId = $null,
            [string] $ManagedBy = '')
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Name              = $Name
            SamAccountName    = $Name
            Sid               = [PSCustomObject]@{ Value = "$script:domainSid-$Rid" }
            PrimaryGroupId    = $PrimaryGroupId
            ManagedBy         = $ManagedBy
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
            [string] $Manager = '',
            [string[]] $Unreadable = @(),
            [switch] $NoController,
            [object[]] $DomainController = @(),
            [object[]] $ExtraComputer = @(),
            [AllowNull()] [string] $DomainSid = $script:domainSid
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $computers = @(Get-PrincipalFixture -Name 'PC1' -Rid '1106' -PrimaryGroupId 515)
        if (-not $NoController) {
            $computers += Get-PrincipalFixture -Name 'DC1' -Rid '1000' -PrimaryGroupId 516
            $computers += Get-PrincipalFixture -Name 'RODC1' -Rid '1001' -PrimaryGroupId 521 `
                -ManagedBy $Manager
        }
        $computers += $ExtraComputer
        $state = [PSCustomObject]@{
            Domain            = [PSCustomObject]@{ DomainSID = $sidValue }
            Users             = @(
                Get-PrincipalFixture -Name 'admin' -Rid '1100'
                Get-PrincipalFixture -Name 'svc_a' -Rid '1105'
            )
            Computers         = $computers
            Groups            = @(
                Get-PrincipalFixture -Name 'Tier0' -Rid '1200'
                Get-PrincipalFixture -Name 'Helpdesk' -Rid '1201'
            )
            DomainControllers = $DomainController
            ProtocolEvidence  = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @(
                $controller = @($computers | Where-Object { $_.PrimaryGroupId -ne 515 })
                foreach ($item in @($state.Users[0]) + $controller) {
                    [PSCustomObject]@{ Item = $item }
                }
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
                $name = ($dn -split ',')[0] -replace '^CN=', ''
                $aceList = @($script:aceByName[$name])
                if ($name -in $script:unreadableName) { $aceList = $null }
                [PSCustomObject]@{
                    DistinguishedName = $dn; Name = $name; ObjectClass = @('top', 'computer')
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

Describe 'Test-MtAnssiAdDcPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights and an empty or trusted RODC manager' -ForEach @(
            @{ Manager = '' }
            @{ Manager = 'CN=Tier0,DC=contoso,DC=com' }
        ) {
            Use-Ad -Manager $Manager -Ace @{
                DC1   = @(Get-AceFixture -Rid '1000' -Mask 0x20 -ObjectType $script:spn)
                RODC1 = @(Get-AceFixture -Rid '1200' -Mask 0xF01FF)
            }

            Test-MtAnssiAdDcPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No principal outside the privileged set .* on the 2 domain'
            }
        }

        It 'fails with severity <Expected> for <Name>' -ForEach @(
            @{
                Name = 'a level 1 right'; Target = 'DC1'; Mask = 0x40000; Type = ''
                Expected = 'Critical'
            }
            @{
                Name = 'a level 2 right'; Target = 'DC1'; Mask = 0x20; Type = 'Spn'
                Expected = 'High'
            }
            @{
                Name = 'the right to change the manager of a writable controller'; Target = 'DC1'
                Mask = 0x20; Type = 'ManagedBy'; Expected = 'High'
            }
            @{
                Name = 'the right to change the manager of an RODC'; Target = 'RODC1'
                Mask = 0x20; Type = 'ManagedBy'; Expected = 'Critical'
            }
        ) {
            $objectType = ''
            if ($Type -eq 'Spn') { $objectType = $script:spn }
            if ($Type -eq 'ManagedBy') { $objectType = $script:managedBy }
            $ace = Get-AceFixture -Rid '1201' -Mask $Mask -ObjectType $objectType
            Use-Ad -Ace @{ $Target = @($ace) }

            Test-MtAnssiAdDcPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 dangerous rights on domain controller objects'
            }
        }

        It 'fails for an RODC managed by <Name>' -ForEach @(
            @{
                Name = 'an untrusted group'; Manager = 'CN=Helpdesk,DC=contoso,DC=com'
                Shown = 'Helpdesk'
            }
            @{ Name = 'a computer account'; Manager = 'CN=PC1,DC=contoso,DC=com'; Shown = 'PC1' }
            @{
                Name = 'a principal outside the collected data'; Manager = 'CN=Gone,DC=other,DC=com'
                Shown = 'CN=Gone,DC=other,DC=com'
            }
        ) {
            Use-Ad -Manager $Manager

            Test-MtAnssiAdDcPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            $pattern = '\| RODC1 \| ' + [regex]::Escape($Shown) +
            ' \| ManagedBy \| Critical \| No \|'
            $filter = [scriptblock]::Create("(`$Result -replace '\\\\', '') -match '$pattern'")
            Should -Invoke @detail -ParameterFilter $filter
        }
    }

    Context 'data read' {
        It 'reads the five state categories' {
            Use-Ad

            $null = Test-MtAnssiAdDcPermission

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 5 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups' -and $Categories -contains 'DomainControllers'
            }
        }

        It 'reads a controller found only through its NTDS settings' {
            $dc2 = Get-PrincipalFixture -Name 'DC2' -Rid '1002' -PrimaryGroupId 515
            $ntds = [PSCustomObject]@{ ServerReference = 'CN=DC2,DC=contoso,DC=com' }
            Use-Ad -ExtraComputer @($dc2) -DomainController @($ntds)

            $null = Test-MtAnssiAdDcPermission

            Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $DistinguishedName -contains 'CN=DC2,DC=contoso,DC=com' }
        }

        It 'reads the objects of the writable and read-only controllers only' {
            Use-Ad

            $null = Test-MtAnssiAdDcPermission

            Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                (@($DistinguishedName | Sort-Object) -join ';') -eq
                'CN=DC1,DC=contoso,DC=com;CN=RODC1,DC=contoso,DC=com' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'admin' -and
                @($Computer)[0].Name -eq 'PC1' -and @($Group)[0].Name -eq 'Tier0' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }
    }

    Context 'skips' {
        It 'lets the exception reach the engine when the state cannot be read' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

            { Test-MtAnssiAdDcPermission } | Should -Throw

        }

        It 'skips when <Name> is missing' -ForEach @(
            @{ Name = 'the domain SID'; Sid = $null; NoController = $false }
            @{ Name = 'every controller'; Sid = 'S-1-5-21-1-2-3'; NoController = $true }
        ) {
            Use-Ad -DomainSid $Sid -NoController:$NoController

            $null -eq (Test-MtAnssiAdDcPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match 'domain controller computer'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
        }

        It 'lets the exception reach the engine when <Name> fails' -ForEach @(
            @{ Name = 'the privileged list'; Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Name = 'the object read'; Command = 'Get-MtAnssiAdObjectSecurity' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdDcPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when the permissions of a controller cannot be read' {
            $ace = Get-AceFixture -Rid '1201' -Mask 0x40000
            Use-Ad -Unreadable @('RODC1') -Ace @{ DC1 = @($ace) }

            $null -eq (Test-MtAnssiAdDcPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match '^The permissions of 1 domain'
            }
        }
    }
}
