BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-062.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrivilegedProtectedUserMembership' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrivilegedProtectedUserMembership {
        InModuleScope Maester { Test-MtAnssiAdPrivilegedProtectedUserMembership }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-Account {
        param(
            [string] $Name,
            [string] $Kind = 'User',
            [AllowNull()] [object] $Enabled = $true,
            [string[]] $Group = @('Domain Admins')
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Kind              = $Kind
            Group             = $Group
            Link              = @('Member')
            Item              = [PSCustomObject]@{
                Name           = $Name
                SamAccountName = $Name
                Enabled        = $Enabled
                LastLogonDate  = [datetime]'2025-06-01'
            }
        }
    }

    function Use-Ad {
        param(
            [object[]] $Account = @(),
            [string[]] $ProtectedName = @(),
            [switch] $NoProtectedGroup,
            [object[]] $Unresolved = @(),
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3'
        )
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{ DomainSID = $domainSidValue }
            Users            = @([PSCustomObject]@{ Name = 'U1' })
            Computers        = @([PSCustomObject]@{ Name = 'C1' })
            Groups           = @([PSCustomObject]@{ Name = 'G1' })
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{ Account = $Account; Unresolved = $Unresolved }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $memberDn = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $ProtectedName) { $null = $memberDn.Add("CN=$name,DC=contoso,DC=com") }
        $groupItem = [PSCustomObject]@{ Name = 'Protected Users' }
        if ($NoProtectedGroup) { $groupItem = $null }
        $protected = [PSCustomObject]@{ Group = $groupItem; MemberDn = $memberDn }
        Mock Get-MtAnssiAdGroupMemberAccount -ModuleName Maester `
            -MockWith ({ $protected }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdPrivilegedProtectedUserMembership' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when every enabled privileged user is in Protected Users' {
            Use-Ad -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob') `
                -ProtectedName 'alice', 'bob'

            Test-MtAnssiAdPrivilegedProtectedUserMembership | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'All 2 enabled privileged user accounts are members'
            }
        }

        It 'fails when an enabled privileged user is not in Protected Users' {
            Use-Ad -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob') `
                -ProtectedName 'bob'

            Test-MtAnssiAdPrivilegedProtectedUserMembership | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 of 2 enabled privileged user accounts are not members' -and
                $Result -match '\| contoso\.com \|' -and
                $Result -notmatch 'does not exist'
            }
        }

        It 'ignores a disabled or unknown-state privileged user' -ForEach @(
            @{ Enabled = $false }
            @{ Enabled = $null }
        ) {
            Use-Ad -Account @(Get-Account -Name 'alice' -Enabled $Enabled)

            Test-MtAnssiAdPrivilegedProtectedUserMembership | Should -Be $true
        }

        It 'ignores a privileged computer account' {
            Use-Ad -Account @(Get-Account -Name 'DC1' -Kind 'Computer')

            Test-MtAnssiAdPrivilegedProtectedUserMembership | Should -Be $true

            Should -Invoke @detail -ParameterFilter { $Result -match 'All 0 enabled' }
        }

        It 'reports every enabled privileged user when the group does not exist' {
            Use-Ad -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob') -NoProtectedGroup

            Test-MtAnssiAdPrivilegedProtectedUserMembership | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^2 of 2 enabled' -and
                $Result -match 'The Protected Users group does not exist in this domain\.'
            }
        }
    }

    Context 'data read' {
        It 'lists the privileged accounts and the Protected Users members from the collected data' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedProtectedUserMembership

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'U1' -and
                @($Computer)[0].Name -eq 'C1' -and @($Group)[0].Name -eq 'G1' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdGroupMemberAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $GroupSid -eq 'S-1-5-21-1-2-3-525' -and @($AdState.Users)[0].Name -eq 'U1'
            }
        }

        It 'reads the Domain, Users, Computers and Groups categories' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedProtectedUserMembership

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
        }
    }

    Context 'result text' {
        It 'lists the accounts by name with the groups they reach and their last logon' {
            Use-Ad -Account @(
                Get-Account -Name 'zed' -Group 'Administrators', 'Domain Admins'
                Get-Account -Name 'amy'
            )

            $null = Test-MtAnssiAdPrivilegedProtectedUserMembership

            Should -Invoke @detail -ParameterFilter {
                $Result -match ('(?s)amy \| Domain Admins \| 2025-06-01 \|.*' +
                    'zed \| Administrators, Domain Admins \| 2025-06-01 \|')
            }
        }

        It 'says how many members were not checked, on a pass and on a failure' -ForEach @(
            @{ Protected = @('alice') }
            @{ Protected = @() }
        ) {
            $unresolved = @([PSCustomObject]@{ DistinguishedName = 'CN=x'; Group = @('G') })
            Use-Ad -Account @(Get-Account -Name 'alice') -ProtectedName $Protected `
                -Unresolved $unresolved

            $null = Test-MtAnssiAdPrivilegedProtectedUserMembership

            Should -Invoke @detail -ParameterFilter { $Result -match 'also hold 1 member\(s\)' }
        }

        It 'escapes markdown in an account name' {
            Use-Ad -Account @(Get-Account -Name '[click](https://evil.example)|x')

            $null = Test-MtAnssiAdPrivilegedProtectedUserMembership

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped without reading when the domain SID is missing' {
            Use-Ad -DomainSid $null

            Test-MtAnssiAdPrivilegedProtectedUserMembership | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
            Should -Invoke Get-MtAnssiAdGroupMemberAccount -ModuleName Maester -Times 0 -Exactly
            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'lets the exception reach the engine when <Helper> fails' -ForEach @(
            @{ Helper = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Helper = 'Get-MtAnssiAdGroupMemberAccount' }
        ) {
            Use-Ad
            Mock $Helper -ModuleName Maester -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdPrivilegedProtectedUserMembership } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdPrivilegedProtectedUserMembership } | Should -Throw 'LDAP bind failed'

        }
    }
}
