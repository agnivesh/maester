BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-054.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdSysvolNtfrsReplication' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdSysvolNtfrsReplication {
        InModuleScope Maester { Test-MtAnssiAdSysvolNtfrsReplication }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-ComputerFixture {
        param(
            [string] $Name = 'DC1',
            [int] $PrimaryGroupId = 516,
            [string] $OperatingSystem = 'Windows Server 2022 Standard'
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            Name              = $Name
            PrimaryGroupId    = $PrimaryGroupId
            OperatingSystem   = $OperatingSystem
        }
    }

    function Get-SubscriptionFixture {
        param([string] $Name = 'DC1')
        [PSCustomObject]@{
            DistinguishedName = 'CN=SYSVOL Subscription,CN=Domain System Volume,' +
            "CN=DFSR-LocalSettings,CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
        }
    }

    function Use-Ad {
        param([object[]] $Computer, [AllowNull()] [object[]] $Subscription)
        $state = [PSCustomObject]@{
            Computers         = $Computer
            DomainControllers = @()
            DfsrSubscriptions = $Subscription
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdSysvolNtfrsReplication' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when every controller has a SYSVOL subscription' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'DC1'; Get-ComputerFixture -Name 'DC2') `
                -Subscription @(
                Get-SubscriptionFixture -Name 'DC1'
                Get-SubscriptionFixture -Name 'DC2'
            )

            Test-MtAnssiAdSysvolNtfrsReplication | Should -Be $true
        }

        It 'fails when one controller has no subscription' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'DC1'; Get-ComputerFixture -Name 'DC2') `
                -Subscription @(Get-SubscriptionFixture -Name 'DC1')

            Test-MtAnssiAdSysvolNtfrsReplication | Should -Be $false
        }

        It 'fails when the domain has no subscription at all' {
            Use-Ad -Computer @(Get-ComputerFixture) -Subscription @()

            Test-MtAnssiAdSysvolNtfrsReplication | Should -Be $false
        }

        It 'checks read-only domain controllers' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'DC1'
                Get-ComputerFixture -Name 'RO1' -PrimaryGroupId 521
            ) -Subscription @(Get-SubscriptionFixture -Name 'DC1')

            Test-MtAnssiAdSysvolNtfrsReplication | Should -Be $false
        }

        It 'ignores computers that are not domain controllers' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'DC1'
                Get-ComputerFixture -Name 'SRV1' -PrimaryGroupId 515
            ) -Subscription @(Get-SubscriptionFixture -Name 'DC1')

            Test-MtAnssiAdSysvolNtfrsReplication | Should -Be $true
        }
    }

    Context 'result text' {
        It 'counts the controllers when the test passes' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'A'; Get-ComputerFixture -Name 'B') `
                -Subscription @(
                Get-SubscriptionFixture -Name 'A'
                Get-SubscriptionFixture -Name 'B'
            )

            $null = Test-MtAnssiAdSysvolNtfrsReplication

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 domain controllers have a SYSVOL DFS Replication'
            }
        }

        It 'lists the controllers without a subscription with type and system, by name' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'GOOD'
                Get-ComputerFixture -Name 'ZED' -PrimaryGroupId 521 `
                    -OperatingSystem 'Windows Server 2012 R2 Standard'
                Get-ComputerFixture -Name 'ABC'
            ) -Subscription @(Get-SubscriptionFixture -Name 'GOOD')

            $null = Test-MtAnssiAdSysvolNtfrsReplication

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^2 of 3 domain controllers' -and $Result -match 'NTFRS' -and
                $Result -match '\| contoso\.com \|' -and
                $Result -match '(?s)ABC \| Writable \| Windows Server 2022 Standard \|.*' +
                'ZED \| ReadOnly \| Windows Server 2012 R2 Standard \|' -and
                $Result -notmatch 'GOOD'
            }
        }

        It 'escapes markdown in the controller name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil) -Subscription @()

            $null = Test-MtAnssiAdSysvolNtfrsReplication

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers, DomainControllers and DfsrSubscriptions categories' {
            Use-Ad -Computer @(Get-ComputerFixture) -Subscription @(Get-SubscriptionFixture)

            $null = Test-MtAnssiAdSysvolNtfrsReplication

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 3 -and $Categories -contains 'Computers' -and
                $Categories -contains 'DomainControllers' -and
                $Categories -contains 'DfsrSubscriptions'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no domain controller computer account is found' {
            Use-Ad -Computer @(Get-ComputerFixture -PrimaryGroupId 515) `
                -Subscription @(Get-SubscriptionFixture)

            Test-MtAnssiAdSysvolNtfrsReplication | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain controller'
            }
        }

        It 'is skipped when the subscriptions were not collected' {
            Use-Ad -Computer @(Get-ComputerFixture) -Subscription $null

            Test-MtAnssiAdSysvolNtfrsReplication | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'subscriptions'
            }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdSysvolNtfrsReplication } | Should -Throw 'LDAP bind failed'

        }
    }
}
