BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-050.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrivilegedPasswordPolicy' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrivilegedPasswordPolicy {
        InModuleScope Maester { Test-MtAnssiAdPrivilegedPasswordPolicy }
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
                Name = $Name; SamAccountName = $Name; Enabled = $Enabled
            }
        }
    }

    function Get-Policy {
        param(
            [object] $Account,
            [string[]] $Weakness = @(),
            [string] $Source = 'Domain password policy'
        )
        [PSCustomObject]@{ Account = $Account; Source = $Source; Weakness = $Weakness }
    }

    function Use-Ad {
        param(
            [object[]] $Account = @(),
            [object[]] $Policy = @(),
            [object[]] $Unresolved = @(),
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3'
        )
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{ DomainSID = $domainSidValue; Name = 'contoso' }
            Users            = @([PSCustomObject]@{ Name = 'U1' })
            Computers        = @([PSCustomObject]@{ Name = 'C1' })
            Groups           = @([PSCustomObject]@{ Name = 'G1' })
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{ Account = $Account; Unresolved = $Unresolved }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $policies = $Policy
        Mock Get-MtAnssiAdEffectivePasswordPolicy -ModuleName Maester `
            -MockWith ({ $policies }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdPrivilegedPasswordPolicy' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when every enabled privileged user has a strong policy' {
            $alice = Get-Account -Name 'alice'
            Use-Ad -Account @($alice) -Policy @(Get-Policy -Account $alice)

            Test-MtAnssiAdPrivilegedPasswordPolicy | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'All 1 enabled privileged user accounts have a strong password'
            }
        }

        It 'fails when an enabled privileged user has a weak policy' {
            $alice = Get-Account -Name 'alice'
            $bob = Get-Account -Name 'bob'
            Use-Ad -Account @($alice, $bob) -Policy @(
                Get-Policy -Account $alice -Weakness 'minimum length 7'
                Get-Policy -Account $bob
            )

            Test-MtAnssiAdPrivilegedPasswordPolicy | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 of 2 enabled privileged user accounts have a weak password' -and
                $Result -match '\| contoso\.com \|'
            }
        }
    }

    Context 'data read' {
        It 'reads the policy of the enabled privileged users only, with the collected domain' {
            Use-Ad -Account @(
                Get-Account -Name 'alice'
                Get-Account -Name 'bob' -Enabled $false
                Get-Account -Name 'carol' -Enabled $null
                Get-Account -Name 'DC1' -Kind 'Computer'
            )

            $null = Test-MtAnssiAdPrivilegedPasswordPolicy

            Should -Invoke Get-MtAnssiAdEffectivePasswordPolicy -ModuleName Maester -Times 1 `
                -Exactly `
                -ParameterFilter {
                @($Account).Count -eq 1 -and @($Account)[0].Item.Name -eq 'alice' -and
                $Domain.Name -eq 'contoso' -and $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }

        It 'lists the privileged accounts from the collected data' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedPasswordPolicy

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'U1' -and
                @($Computer)[0].Name -eq 'C1' -and @($Group)[0].Name -eq 'G1' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }

        It 'reads the Domain, Users, Computers and Groups categories' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedPasswordPolicy

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
        }
    }

    Context 'result text' {
        It 'lists the accounts by name with the policy, its weaknesses and the groups' {
            $zed = Get-Account -Name 'zed' -Group 'Administrators', 'Domain Admins'
            $amy = Get-Account -Name 'amy'
            Use-Ad -Account @($zed, $amy) -Policy @(
                Get-Policy -Account $zed -Weakness 'minimum length 6', 'passwords never expire'
                Get-Policy -Account $amy -Weakness 'maximum age 2000 days' `
                    -Source 'Fine-grained policy Old'
            )

            $null = Test-MtAnssiAdPrivilegedPasswordPolicy

            Should -Invoke @detail -ParameterFilter {
                $Result -match ('(?s)amy \| Fine-grained policy Old \| maximum age 2000 days \| ' +
                    'Domain Admins \|.*zed \| Domain password policy \| minimum length 6; ' +
                    'passwords never expire \| Administrators, Domain Admins \|')
            }
        }

        It 'says how many members were not checked, on a pass and on a failure' -ForEach @(
            @{ Weakness = @() }
            @{ Weakness = @('minimum length 7') }
        ) {
            $alice = Get-Account -Name 'alice'
            $unresolved = @([PSCustomObject]@{ DistinguishedName = 'CN=x'; Group = @('G') })
            Use-Ad -Account @($alice) -Policy @(Get-Policy -Account $alice -Weakness $Weakness) `
                -Unresolved $unresolved

            $null = Test-MtAnssiAdPrivilegedPasswordPolicy

            Should -Invoke @detail -ParameterFilter { $Result -match 'also hold 1 member\(s\)' }
        }

        It 'escapes markdown in an account name' {
            $account = Get-Account -Name '[click](https://evil.example)|x'
            Use-Ad -Account @($account) -Policy @(Get-Policy -Account $account -Weakness 'x')

            $null = Test-MtAnssiAdPrivilegedPasswordPolicy

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped without reading when the domain SID is missing' {
            Use-Ad -DomainSid $null

            Test-MtAnssiAdPrivilegedPasswordPolicy | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'lets the exception reach the engine when <Helper> fails' -ForEach @(
            @{ Helper = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Helper = 'Get-MtAnssiAdEffectivePasswordPolicy' }
        ) {
            Use-Ad
            Mock $Helper -ModuleName Maester -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdPrivilegedPasswordPolicy } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdPrivilegedPasswordPolicy } | Should -Throw 'LDAP bind failed'

        }
    }
}
