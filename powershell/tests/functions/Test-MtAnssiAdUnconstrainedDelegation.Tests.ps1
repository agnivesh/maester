BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-011.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdUnconstrainedDelegation' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdUnconstrainedDelegation {
        InModuleScope Maester { Test-MtAnssiAdUnconstrainedDelegation }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-UserFixture {
        param([string] $Name = 'svc1', [bool] $Trusted = $true)
        [PSCustomObject]@{
            SamAccountName       = $Name
            Enabled              = $true
            TrustedForDelegation = $Trusted
            LastLogonDate        = (Get-Date).ToUniversalTime().AddDays(-3)
        }
    }

    function Get-ComputerFixture {
        param(
            [string] $Name = 'SRV1',
            [int] $PrimaryGroupId = 515,
            [bool] $Trusted = $true,
            [AllowNull()] [Nullable[datetime]] $LastLogon = $null
        )
        [PSCustomObject]@{
            DistinguishedName    = "CN=$Name,CN=Computers,DC=contoso,DC=com"
            SamAccountName       = "$Name$"
            OperatingSystem      = 'Windows Server 2022 Standard'
            PrimaryGroupId       = $PrimaryGroupId
            Enabled              = $true
            TrustedForDelegation = $Trusted
            LastLogonDate        = $LastLogon
        }
    }

    function Use-Ad {
        param([object[]] $User = @(), [object[]] $Computer = @())
        $state = [PSCustomObject]@{ Users = $User; Computers = $Computer; DomainControllers = @() }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdUnconstrainedDelegation' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when only domain controllers are trusted for delegation' {
            Use-Ad -User @(Get-UserFixture -Trusted $false) -Computer @(
                Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516
                Get-ComputerFixture -Name 'SRV1' -Trusted $false
            )

            Test-MtAnssiAdUnconstrainedDelegation | Should -BeTrue
        }

        It 'fails when a user account is trusted for delegation' {
            Use-Ad -User @(Get-UserFixture) -Computer @(Get-ComputerFixture -Trusted $false)

            Test-MtAnssiAdUnconstrainedDelegation | Should -Be $false
        }

        It 'fails when a member server is trusted for delegation' {
            Use-Ad -User @(Get-UserFixture -Trusted $false) -Computer @(Get-ComputerFixture)

            Test-MtAnssiAdUnconstrainedDelegation | Should -Be $false
        }

        It 'does not fail for a read-only domain controller' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'RO1' -PrimaryGroupId 521)

            Test-MtAnssiAdUnconstrainedDelegation | Should -BeTrue
        }

        It 'runs with users only' {
            Use-Ad -User @(Get-UserFixture -Trusted $false)

            Test-MtAnssiAdUnconstrainedDelegation | Should -BeTrue
        }
    }

    Context 'result text' {
        It 'says no account is trusted when the test passes' {
            Use-Ad -Computer @(Get-ComputerFixture -Trusted $false)

            $null = Test-MtAnssiAdUnconstrainedDelegation

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^No enabled account other than a domain controller is trusted '
            }
        }

        It 'lists the accounts with type, system and last logon, computers before users' {
            Use-Ad -User @(Get-UserFixture -Name 'asvc') -Computer @(
                Get-ComputerFixture -Name 'ZSRV' -LastLogon ([datetime]'2026-09-01')
                Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516
            )

            $null = Test-MtAnssiAdUnconstrainedDelegation

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^2 enabled accounts' -and
                $Result -match '(?s)Computer \| ZSRV\$ \| Windows Server 2022 Standard \| ' +
                '2026-09-01 \|.*User \| asvc \| +\| \d{4}-\d{2}-\d{2} \|' -and
                $Result -notmatch 'DC1'
            }
        }

        It 'shows Never for an account that never logged on' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'SRV1')

            $null = Test-MtAnssiAdUnconstrainedDelegation

            Should -Invoke @detail -ParameterFilter { $Result -match 'SRV1\$ \| .* \| Never \|' }
        }

        It 'escapes markdown in the account name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -User @(Get-UserFixture -Name $evil)

            $null = Test-MtAnssiAdUnconstrainedDelegation

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Users, Computers and DomainControllers categories' {
            Use-Ad -User @(Get-UserFixture -Trusted $false)

            $null = Test-MtAnssiAdUnconstrainedDelegation

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 3 -and $Categories -contains 'Users' -and
                $Categories -contains 'Computers' -and $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when there is no user or computer data' {
            Use-Ad

            Test-MtAnssiAdUnconstrainedDelegation | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'user or computer'
            }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdUnconstrainedDelegation } | Should -Throw 'LDAP bind failed'

        }
    }

    It 'is skipped when the <Collection> collection was not returned' -ForEach @(
        @{ Collection = 'Users' }
        @{ Collection = 'Computers' }
        @{ Collection = 'DomainControllers' }
    ) {
        $props = [ordered]@{ Users = @(); Computers = @(); DomainControllers = @() }
        $props[$Collection] = $null
        $state = [PSCustomObject]$props
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

        Test-MtAnssiAdUnconstrainedDelegation | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
