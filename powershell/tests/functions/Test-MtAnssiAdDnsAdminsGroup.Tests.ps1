BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-013.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDnsAdminsGroup' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDnsAdminsGroup {
        InModuleScope Maester { Test-MtAnssiAdDnsAdminsGroup }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:member = 'bf9679c0-0de6-11d0-a285-00aa003049e2'

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
            [object[]] $Ace = @(),
            [string[]] $MemberDn = @(),
            [string[]] $NestedGroup = @(),
            [string[]] $Unresolved = @(),
            [switch] $NoGroup,
            [switch] $Unreadable,
            [AllowNull()] [string] $DomainSid = $script:domainSid
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $admin = Get-PrincipalFixture -Name 'admin' -Rid '1100'
        $groups = @(Get-PrincipalFixture -Name 'Tier0' -Rid '1200')
        if (-not $NoGroup) { $groups += Get-PrincipalFixture -Name 'DnsAdmins' -Rid '1101' }
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{ DomainSID = $sidValue }
            Users            = @($admin; Get-PrincipalFixture -Name 'svc_dns' -Rid '1105')
            Computers        = @(Get-PrincipalFixture -Name 'PC1$' -Rid '1106')
            Groups           = $groups
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{
            Account    = @([PSCustomObject]@{ Item = $admin })
            Unresolved = @(
                [PSCustomObject]@{ DistinguishedName = 'CN=x'; Group = @('Domain Admins') }
            )
            Group      = @('CN=Tier0,DC=contoso,DC=com')
        }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $membership = [PSCustomObject]@{
            Group = $groups[-1]; MemberDn = $MemberDn; NestedGroup = $NestedGroup
            Unresolved = $Unresolved
        }
        Mock Get-MtAnssiAdGroupMemberAccount -ModuleName Maester `
            -MockWith ({ $membership }.GetNewClosure())
        $aceList = $Ace
        if ($Unreadable) { $aceList = $null }
        $target = [PSCustomObject]@{
            DistinguishedName = 'CN=DnsAdmins,DC=contoso,DC=com'; Name = 'DnsAdmins'
            ObjectClass = @('top', 'group'); OwnerSid = "$script:domainSid-512"; Ace = $aceList
        }
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith ({ $target }.GetNewClosure())
    }

    function Get-Plain {
        param([string] $Text)
        $Text -replace '\\', ''
    }
}

Describe 'Test-MtAnssiAdDnsAdminsGroup' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when the group is empty and only trusted principals control it' {
            Use-Ad -Ace @(Get-AceFixture -Rid '1200' -Mask 0xF01FF)

            Test-MtAnssiAdDnsAdminsGroup | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^DnsAdmins has no member and no principal outside' -and
                $Result -match 'not checked'
            }
        }

        It 'passes without reading anything when the domain has no DnsAdmins group' {
            Use-Ad -NoGroup

            Test-MtAnssiAdDnsAdminsGroup | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -eq 'The domain has no group named DnsAdmins.'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
        }

        It 'fails for a member of kind <Kind>' -ForEach @(
            @{ Kind = 'Account'; Member = @('CN=svc_dns,DC=x'); Nested = @(); Missing = @() }
            @{ Kind = 'Group'; Member = @(); Nested = @('CN=Empty,DC=x'); Missing = @() }
            @{ Kind = 'Not collected'; Member = @(); Nested = @(); Missing = @('CN=S-1-5-11') }
        ) {
            Use-Ad -MemberDn $Member -NestedGroup $Nested -Unresolved $Missing

            Test-MtAnssiAdDnsAdminsGroup | Should -Be $false

            $expected = "\| [^|]+ \| $Kind \|"
            $filter = [scriptblock]::Create(
                "`$Result -match '^DnsAdmins has 1 members and 0 dangerous rights' -and " +
                "(`$Result -replace '\\\\', '') -match '$expected'")
            Should -Invoke @detail -ParameterFilter $filter
        }

        It 'lists members by kind, then name' {
            Use-Ad -MemberDn @('CN=zed,DC=x', 'CN=amy,DC=x') -NestedGroup @('CN=Grp,DC=x') `
                -Unresolved @('CN=S-1-5-11,CN=FSP')

            $null = Test-MtAnssiAdDnsAdminsGroup

            Should -Invoke @detail -ParameterFilter {
                (Get-Plain -Text $Result) -match ('(?s)CN=amy,DC=x \| Account.*' +
                    'CN=zed,DC=x \| Account.*' +
                    'CN=Grp,DC=x \| Group.*CN=S-1-5-11,CN=FSP \| Not collected')
            }
        }

        It 'fails for an untrusted <Name>, shown as Critical' -ForEach @(
            @{ Name = 'member write'; Mask = 0x20; Member = $true }
            @{ Name = 'validated write on a group'; Mask = 0x8; Member = $false }
        ) {
            $objectType = ''
            if ($Member) { $objectType = $script:member }
            Use-Ad -Ace @(Get-AceFixture -Rid '1105' -Mask $Mask -ObjectType $objectType)

            Test-MtAnssiAdDnsAdminsGroup | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'has 0 members and 1 dangerous rights' -and
                (Get-Plain -Text $Result) -match
                '\| DnsAdmins \| svc_dns \| WriteMember \| Critical \|'
            }
        }

        It 'shows a level 2 right as Critical' {
            $spn = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
            Use-Ad -Ace @(Get-AceFixture -Rid '1105' -Mask 0x20 -ObjectType $spn)

            Test-MtAnssiAdDnsAdminsGroup | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                (Get-Plain -Text $Result) -match '\| svc_dns \| WriteSpn \| Critical \|'
            }
        }
    }

    Context 'data read' {
        It 'reads the members and the permissions of DnsAdmins' {
            Use-Ad

            $null = Test-MtAnssiAdDnsAdminsGroup

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
            Should -Invoke Get-MtAnssiAdGroupMemberAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $GroupSid -eq 'S-1-5-21-1-2-3-1101' -and $AdState.Groups.Count -eq 2
            }
            Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                (@($DistinguishedName) -join ';') -eq 'CN=DnsAdmins,DC=contoso,DC=com' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
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

            { Test-MtAnssiAdDnsAdminsGroup } | Should -Throw

        }

        It 'skips when the domain SID is missing' {
            Use-Ad -DomainSid $null

            $null -eq (Test-MtAnssiAdDnsAdminsGroup) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'lets the exception reach the engine when <Command> fails' -ForEach @(
            @{ Command = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Command = 'Get-MtAnssiAdGroupMemberAccount' }
            @{ Command = 'Get-MtAnssiAdObjectSecurity' }
        ) {
            Use-Ad
            Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

            { Test-MtAnssiAdDnsAdminsGroup } | Should -Throw '*LDAP failed*'

        }

        It 'skips when the permissions of DnsAdmins cannot be read' {
            Use-Ad -Unreadable

            $null -eq (Test-MtAnssiAdDnsAdminsGroup) | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'could not be read'
            }
        }
    }

    It 'is skipped when the <Collection> collection was not returned' -ForEach @(
        @{ Collection = 'Users' }
        @{ Collection = 'Computers' }
        @{ Collection = 'Groups' }
    ) {
        $props = [ordered]@{ Users = @(); Computers = @(); Groups = @() }
        $props[$Collection] = $null
        $state = [PSCustomObject]$props
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

        Test-MtAnssiAdDnsAdminsGroup | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
