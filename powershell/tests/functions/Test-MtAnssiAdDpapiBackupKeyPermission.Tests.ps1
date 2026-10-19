BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-025.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDpapiBackupKeyPermission' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDpapiBackupKeyPermission {
        InModuleScope Maester { Test-MtAnssiAdDpapiBackupKeyPermission }
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
            [AllowNull()] [string] $DomainSid = $script:domainSid
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $admin = Get-PrincipalFixture -Name 'admin' -Rid '1100'
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID = $sidValue; DistinguishedName = 'DC=contoso,DC=com'
            }
            Users            = @($admin; Get-PrincipalFixture -Name 'key_op' -Rid '1105')
            Computers        = @(Get-PrincipalFixture -Name 'PC1$' -Rid '1106')
            Groups           = @(Get-PrincipalFixture -Name 'Tier0' -Rid '1200')
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @([PSCustomObject]@{ Item = $admin })
            Unresolved = @()
            Group      = @('CN=Tier0,DC=contoso,DC=com')
        }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        Mock Get-MtAnssiAdNamingContextHead -ModuleName Maester -MockWith {
            'DC=contoso,DC=com'
            'CN=Configuration,DC=contoso,DC=com'
            'CN=Schema,CN=Configuration,DC=contoso,DC=com'
        }
        $aceList = $Ace
        if ($Unreadable) { $aceList = $null }
        $script:objects = @([PSCustomObject]@{
                DistinguishedName = 'CN=BCKUPKEY_P Secret,CN=System,DC=contoso,DC=com'
                Name = 'BCKUPKEY_P Secret'
                ObjectClass = @('top', 'secret'); OwnerSid = "$script:domainSid-512"
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

Describe 'Test-MtAnssiAdDpapiBackupKeyPermission' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with only trusted rights and reports the most severe level' {
            Use-Ad -Ace @(Get-AceFixture -Rid '1200' -Mask 0xF01FF)

            Test-MtAnssiAdDpapiBackupKeyPermission | Should -Be $true

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
            Should -Invoke @detail -ParameterFilter {
                $Result -match ('^No principal outside the privileged set .* on the 1 DPAPI' +
                    ' backup keys')
            }
        }

        It 'fails with severity <Expected> for <Name>' -ForEach @(
            @{
                Name = 'a level 1 right'
                Mask = 0x40000
                Right = 'WriteDacl'
                Expected = 'Critical'
            }
            @{
                Name = 'a level 2 right'
                Mask = 0x8
                Right = 'AllValidatedWrites'
                Expected = 'High'
            }
        ) {
            Use-Ad -Ace @(Get-AceFixture -Rid '1105' -Mask $Mask)

            Test-MtAnssiAdDpapiBackupKeyPermission | Should -Be $false

            Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
            $pattern = ('(?s)^1 dangerous rights on DPAPI backup keys.*\| BCKUPKEY_P Secret \|' +
                ' key_op \| ') + $Right
            $filter = [scriptblock]::Create("(`$Result -replace '\\', '') -match '$pattern'")
            Should -Invoke @detail -ParameterFilter $filter
        }
    }

    Context 'data read' {
        It 'reads the objects the test judges' {
            Use-Ad

            $null = Test-MtAnssiAdDpapiBackupKeyPermission

            Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                ($SearchBase -join ';') -eq 'CN=System,DC=contoso,DC=com' -and
                    $Scope -eq 'OneLevel' -and
                $Filter -eq '(&(objectClass=secret)(cn=BCKUPKEY*))' -and
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
        }
    }

    Context 'skips' {
        It 'lets the exception reach the engine when the state cannot be read' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

            { Test-MtAnssiAdDpapiBackupKeyPermission } | Should -Throw

        }

        It 'skips when the domain SID is missing' {
            Use-Ad -DomainSid $null

            $null -eq (Test-MtAnssiAdDpapiBackupKeyPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
        }

        It 'lets the exception reach the engine when <Command> fails' -ForEach @(
            @{ Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Command = 'Get-MtAnssiAdSearchSecurity' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdDpapiBackupKeyPermission } | Should -Throw '*LDAP failed*'

        }

        It 'skips when the permissions of an object cannot be read' {
            Use-Ad -Unreadable

            $null -eq (Test-MtAnssiAdDpapiBackupKeyPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'could not be read'
            }
        }

        It 'skips when no backup key object is found' {
            Use-Ad -NoObject

            $null -eq (Test-MtAnssiAdDpapiBackupKeyPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                    $SkippedCustomReason -match 'No DPAPI backup key object'
            }
        }

        It 'skips when the domain name is missing' {
            Use-Ad
            $state = [PSCustomObject]@{
                Domain = [PSCustomObject]@{
                    DomainSID = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3' }
                }
                Users  = @(); Computers = @(); Groups = @()
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null -eq (Test-MtAnssiAdDpapiBackupKeyPermission) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID or name'
            }
        }
    }
}
