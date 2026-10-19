BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-024.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDfsrSysvolPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDfsrSysvolPermission {
        InModuleScope Maester { Test-MtAnssiAdDfsrSysvolPermission }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:topology = ('CN=Topology,CN=Domain System' +
        ' Volume,CN=DFSR-GlobalSettings,CN=System,DC=contoso,DC=com')

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
        param([string] $Rid, [uint32] $Mask)
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = ''; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = "$script:domainSid-$Rid"
        }
    }

    function Use-Ad {
        param(
            [object[]] $Ace = @(),
            [switch] $NoObject,
            [switch] $Unreadable,
            [AllowNull()] [string] $DomainSid = $script:domainSid,
            [AllowNull()] [string] $DomainDn = 'DC=contoso,DC=com'
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $admin = Get-PrincipalFixture -Name 'admin' -Rid '1100'
        $state = [PSCustomObject]@{
            Domain            = [PSCustomObject]@{
                DomainSID = $sidValue
                DistinguishedName = $DomainDn
            }
            Users             = @($admin; Get-PrincipalFixture -Name 'file_op' -Rid '1105')
            Computers         = @(Get-PrincipalFixture -Name 'DC1' -Rid '1000')
            Groups            = @(Get-PrincipalFixture -Name 'Tier0' -Rid '1200')
            DomainControllers = @([PSCustomObject]@{ ServerReference = 'CN=DC1,DC=contoso,DC=com' })
            ProtocolEvidence  = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @([PSCustomObject]@{ Item = $admin })
            Unresolved = @()
            Group      = @('CN=Tier0,DC=contoso,DC=com')
        }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $aceList = $Ace
        if ($Unreadable) { $aceList = $null }
        $objects = @([PSCustomObject]@{
                DistinguishedName = $script:topology; Name = 'Topology'
                ObjectClass = @('top', 'msDFSR-Topology'); OwnerSid = "$script:domainSid-512"
                Ace = $aceList
            })
        if ($NoObject) { $objects = @() }
        Mock Get-MtAnssiAdDfsrSysvolObject -ModuleName Maester `
            -MockWith ({ $objects }.GetNewClosure())
    }

    function Get-Severity {
        param([string] $Expected)
        [scriptblock]::Create("`$Severity -eq '$Expected'")
    }
}

Describe 'Test-MtAnssiAdDfsrSysvolPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights and reports the most severe level' {
            Use-Ad -Ace @(Get-AceFixture -Rid '1200' -Mask 0xF01FF)

            Test-MtAnssiAdDfsrSysvolPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter {
                $Result -match ('^No principal outside the privileged set .* on the 1 SYSVOL' +
                    ' DFSR objects')
            }
        }

        It 'skips when no SYSVOL DFSR object is visible' {
            Use-Ad -NoObject
            $null -eq (Test-MtAnssiAdDfsrSysvolPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match '^No SYSVOL DFSR object is visible'
            }
        }

        It 'fails with severity <Expected> for <Name>, shown below the domain' -ForEach @(
            @{
                Name = 'a level 1 right'
                Mask = 0x40000
                Right = 'WriteDacl'
                Expected = 'Critical'
            }
            @{ Name = 'adding a member'; Mask = 0x1; Right = 'CreateChild'; Expected = 'High' }
        ) {
            Use-Ad -Ace @(Get-AceFixture -Rid '1105' -Mask $Mask)

            Test-MtAnssiAdDfsrSysvolPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
            $pattern = ('(?s)^1 dangerous rights on SYSVOL DFSR objects.*\|' +
                ' ') + [regex]::Escape(($script:topology -replace ',DC=contoso,DC=com$', '')) +
            ' \| file_op \| ' + $Right + ' \|'
            $filter = [scriptblock]::Create("(`$Result -replace '\\', '') -match '$pattern'")
            Should -Invoke @detail -ParameterFilter $filter
        }
    }

    Context 'data read' {
        It 'reads the DFSR objects of the domain and its controllers' {
            Use-Ad

            $null = Test-MtAnssiAdDfsrSysvolPermission

            Should -Invoke Get-MtAnssiAdDfsrSysvolObject -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainDn -eq 'DC=contoso,DC=com' -and @($Computer)[0].Name -eq 'DC1' -and
                @($DomainController)[0].ServerReference -eq 'CN=DC1,DC=contoso,DC=com' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 5 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups' -and $Categories -contains 'DomainControllers'
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

            { Test-MtAnssiAdDfsrSysvolPermission } | Should -Throw

        }

        It 'skips when the domain <Name> is missing' -ForEach @(
            @{ Name = 'SID'; Sid = $null; Dn = 'DC=contoso,DC=com' }
            @{ Name = 'name'; Sid = 'S-1-5-21-1-2-3'; Dn = $null }
        ) {
            Use-Ad -DomainSid $Sid -DomainDn $Dn

            $null -eq (Test-MtAnssiAdDfsrSysvolPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID or name'
            }
        }

        It 'lets the exception reach the engine when <Command> fails' -ForEach @(
            @{ Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Command = 'Get-MtAnssiAdDfsrSysvolObject' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdDfsrSysvolPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when the permissions of an object cannot be read' {
            Use-Ad -Unreadable

            $null -eq (Test-MtAnssiAdDfsrSysvolPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'could not be read'
            }
        }
    }
}
