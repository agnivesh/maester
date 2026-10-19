BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-074.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrivilegedAuthenticationSilo' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrivilegedAuthenticationSilo {
        InModuleScope Maester { Test-MtAnssiAdPrivilegedAuthenticationSilo }
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
            [string] $Rid = '2000',
            [AllowNull()] [object] $Enabled = $true,
            [string[]] $Link = @('Member'),
            [string[]] $Group = @('Domain Admins')
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Kind              = $Kind
            Group             = $Group
            Link              = $Link
            Item              = [PSCustomObject]@{
                Name           = $Name
                SamAccountName = $Name
                Enabled        = $Enabled
                Sid            = [PSCustomObject]@{ Value = "S-1-5-21-1-2-3-$Rid" }
            }
        }
    }

    function Get-Status {
        param([object] $Account, [string] $Silo = '', [AllowNull()] [string] $Problem = $null)
        [PSCustomObject]@{ Account = $Account; Silo = $Silo; Problem = $Problem }
    }

    function Use-Ad {
        param(
            [object[]] $Account = @(),
            [object[]] $Status = @(),
            [object[]] $Controller = @(),
            [object[]] $Unresolved = @(),
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3'
        )
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain            = [PSCustomObject]@{ DomainSID = $domainSidValue }
            Users             = @([PSCustomObject]@{ Name = 'U1' })
            Computers         = @([PSCustomObject]@{ Name = 'C1' })
            Groups            = @([PSCustomObject]@{ Name = 'G1' })
            DomainControllers = @([PSCustomObject]@{ Name = 'D1' })
            ProtocolEvidence  = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{ Account = $Account; Unresolved = $Unresolved }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $controllers = $Controller
        Mock Get-MtAnssiAdDomainController -ModuleName Maester `
            -MockWith ({ $controllers }.GetNewClosure())
        $statuses = $Status
        Mock Get-MtAnssiAdSiloAssignment -ModuleName Maester `
            -MockWith ({ $statuses }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdPrivilegedAuthenticationSilo' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when every checked privileged account is in an enforced silo' {
            $alice = Get-Account -Name 'alice'
            Use-Ad -Account @($alice) -Status @(Get-Status -Account $alice -Silo 'Tier0')

            Test-MtAnssiAdPrivilegedAuthenticationSilo | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'All 1 checked privileged accounts are in an enforced'
            }
        }

        It 'fails when a checked privileged account is not properly in a silo' {
            $alice = Get-Account -Name 'alice'
            $bob = Get-Account -Name 'bob'
            Use-Ad -Account @($alice, $bob) -Status @(
                Get-Status -Account $alice -Problem 'not assigned to a silo'
                Get-Status -Account $bob -Silo 'Tier0'
            )

            Test-MtAnssiAdPrivilegedAuthenticationSilo | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 of 2 checked privileged accounts are not properly' -and
                $Result -match '\| contoso\.com \|'
            }
        }
    }

    Context 'data read' {
        It 'checks the enabled group members only, without RID 500 and domain controllers' {
            $computer = [PSCustomObject]@{ DistinguishedName = 'CN=DC1,DC=contoso,DC=com' }
            Use-Ad -Account @(
                Get-Account -Name 'alice'
                Get-Account -Name 'bob' -Enabled $false
                Get-Account -Name 'carol' -Enabled $null
                Get-Account -Name 'Administrator' -Rid '500' -Link 'Member', 'ProtectedAccount'
                Get-Account -Name 'krbtgt' -Rid '502' -Link 'ProtectedAccount' -Enabled $false
                Get-Account -Name 'DC1' -Kind 'Computer' -Rid '1000' -Link 'PrimaryGroup'
                Get-Account -Name 'SRV1' -Kind 'Computer' -Rid '1001'
            ) -Controller @([PSCustomObject]@{ Type = 'Writable'; Computer = $computer })

            $null = Test-MtAnssiAdPrivilegedAuthenticationSilo

            Should -Invoke Get-MtAnssiAdSiloAssignment -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                (@($Account | ForEach-Object { $_.Item.Name }) -join ',') -eq 'alice,SRV1' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdDomainController -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Computer)[0].Name -eq 'C1' -and @($DomainController)[0].Name -eq 'D1'
            }
        }

        It 'lists the privileged accounts from the collected data' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedAuthenticationSilo

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'U1' -and
                @($Computer)[0].Name -eq 'C1' -and @($Group)[0].Name -eq 'G1' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }

        It 'reads the Domain, Users, Computers, Groups and DomainControllers categories' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedAuthenticationSilo

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 5 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups' -and $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'result text' {
        It 'lists the accounts by name with their type, silo, problem and groups' {
            $zed = Get-Account -Name 'zed' -Group 'Administrators', 'Domain Admins'
            $amy = Get-Account -Name 'amy' -Kind 'Computer'
            Use-Ad -Account @($zed, $amy) -Status @(
                Get-Status -Account $zed -Problem 'not assigned to a silo'
                Get-Status -Account $amy -Silo 'Tier0' -Problem 'silo not enforced'
            )

            $null = Test-MtAnssiAdPrivilegedAuthenticationSilo

            Should -Invoke @detail -ParameterFilter {
                $Result -match ('(?s)amy \| Computer \| Tier0 \| silo not enforced \| ' +
                    'Domain Admins \|.*zed \| User \|  \| not assigned to a silo \| ' +
                    'Administrators, Domain Admins \|')
            }
        }

        It 'says how many members were not checked, on a pass and on a failure' -ForEach @(
            @{ Problem = $null }
            @{ Problem = 'silo not enforced' }
        ) {
            $alice = Get-Account -Name 'alice'
            $unresolved = @([PSCustomObject]@{ DistinguishedName = 'CN=x'; Group = @('G') })
            Use-Ad -Account @($alice) -Status @(Get-Status -Account $alice -Problem $Problem) `
                -Unresolved $unresolved

            $null = Test-MtAnssiAdPrivilegedAuthenticationSilo

            Should -Invoke @detail -ParameterFilter { $Result -match 'also hold 1 member\(s\)' }
        }

        It 'escapes markdown in an account name' {
            $account = Get-Account -Name '[click](https://evil.example)|x'
            Use-Ad -Account @($account) -Status @(Get-Status -Account $account -Problem 'x')

            $null = Test-MtAnssiAdPrivilegedAuthenticationSilo

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped without reading when the domain SID is missing' {
            Use-Ad -DomainSid $null

            Test-MtAnssiAdPrivilegedAuthenticationSilo | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'lets the exception reach the engine when <Helper> fails' -ForEach @(
            @{ Helper = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Helper = 'Get-MtAnssiAdSiloAssignment' }
        ) {
            Use-Ad
            Mock $Helper -ModuleName Maester -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdPrivilegedAuthenticationSilo } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdPrivilegedAuthenticationSilo } | Should -Throw 'LDAP bind failed'

        }
    }
}
