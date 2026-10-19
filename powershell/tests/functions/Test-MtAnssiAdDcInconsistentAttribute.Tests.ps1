BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-006.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDcInconsistentAttribute' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDcInconsistentAttribute {
        InModuleScope Maester { Test-MtAnssiAdDcInconsistentAttribute }
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
            [int] $Flags = 532480,
            [int] $PrimaryGroupId = 516
        )
        [PSCustomObject]@{
            DistinguishedName  = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            Name               = $Name
            UserAccountControl = $Flags
            PrimaryGroupId     = $PrimaryGroupId
        }
    }

    function Get-EntryFixture {
        param([string] $Name = 'DC1')
        [PSCustomObject]@{
            Name            = $Name
            ServerReference = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
        }
    }

    function Use-Ad {
        param([object[]] $Computer, [object[]] $Entry = @())
        $state = [PSCustomObject]@{ Computers = $Computer; DomainControllers = $Entry }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDcInconsistentAttribute' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes for a consistent writable controller' {
            Use-Ad -Computer @(Get-ComputerFixture) -Entry @(Get-EntryFixture)

            Test-MtAnssiAdDcInconsistentAttribute | Should -BeTrue
        }

        It 'passes for a consistent read-only controller' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'RO1' -Flags 83890176 -PrimaryGroupId 521)

            Test-MtAnssiAdDcInconsistentAttribute | Should -BeTrue
        }

        It 'fails when a writable controller lacks a flag' {
            Use-Ad -Computer @(Get-ComputerFixture -Flags 0x2000) -Entry @(Get-EntryFixture)

            Test-MtAnssiAdDcInconsistentAttribute | Should -Be $false
        }

        It 'fails when a writable controller has no controller entry' {
            Use-Ad -Computer @(Get-ComputerFixture)

            Test-MtAnssiAdDcInconsistentAttribute | Should -Be $false
        }

        It 'fails when a read-only controller lacks a flag' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'RO1' -Flags 0x1000 -PrimaryGroupId 521)

            Test-MtAnssiAdDcInconsistentAttribute | Should -Be $false
        }

        It 'fails for an ordinary computer that has a controller entry' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'PC1' -Flags 4096 -PrimaryGroupId 515) `
                -Entry @(Get-EntryFixture -Name 'PC1')

            Test-MtAnssiAdDcInconsistentAttribute | Should -Be $false
        }

        It 'ignores computers that are not domain controllers' {
            Use-Ad -Computer @(
                Get-ComputerFixture
                Get-ComputerFixture -Name 'PC1' -Flags 4096 -PrimaryGroupId 515
            ) -Entry @(Get-EntryFixture)

            Test-MtAnssiAdDcInconsistentAttribute | Should -BeTrue
        }
    }

    Context 'result text' {
        It 'counts the controllers when the test passes' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'A'; Get-ComputerFixture -Name 'B') `
                -Entry @(Get-EntryFixture -Name 'A'; Get-EntryFixture -Name 'B')

            $null = Test-MtAnssiAdDcInconsistentAttribute

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 domain controller computer accounts have the expected'
            }
        }

        It 'lists each problem with its controller and type, and counts affected controllers' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'GOOD'
                Get-ComputerFixture -Name 'BAD' -Flags 0
                Get-ComputerFixture -Name 'RO1' -Flags 0x1000 -PrimaryGroupId 521
            ) -Entry @(Get-EntryFixture -Name 'GOOD'; Get-EntryFixture -Name 'BAD')

            $null = Test-MtAnssiAdDcInconsistentAttribute

            Should -Invoke @detail -ParameterFilter {
                $plain = $Result -replace '\\', ''
                $plain -match '2 of 3 domain controller computer accounts' -and
                $plain -match 'BAD \| Writable \| The userAccountControl attribute lacks the S' -and
                $plain -match 'lacks the SERVER_TRUST_ACCOUNT flag' -and
                $plain -match 'lacks the TRUSTED_FOR_DELEGATION flag' -and
                $plain -match 'RO1 \| ReadOnly \| The userAccountControl attribute lacks the P' -and
                $plain -match 'lacks the PARTIAL_SECRETS_ACCOUNT flag' -and
                $plain -notmatch 'GOOD'
            }
        }

        It 'lists the controllers in name order' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'ZED' -Flags 0
                Get-ComputerFixture -Name 'ABC' -Flags 0
            )

            $null = Test-MtAnssiAdDcInconsistentAttribute

            Should -Invoke @detail -ParameterFilter { $Result -match '(?s)ABC \|.*ZED \|' }
        }

        It 'escapes markdown in the controller name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -Flags 0)

            $null = Test-MtAnssiAdDcInconsistentAttribute

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers and DomainControllers categories' {
            Use-Ad -Computer @(Get-ComputerFixture) -Entry @(Get-EntryFixture)

            $null = Test-MtAnssiAdDcInconsistentAttribute

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Computers' -and
                $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no domain controller computer account is found' {
            Use-Ad -Computer @(Get-ComputerFixture -PrimaryGroupId 515)

            Test-MtAnssiAdDcInconsistentAttribute | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain controller'
            }
        }

        It 'is skipped when there is no computer data' {
            Use-Ad -Computer $null

            Test-MtAnssiAdDcInconsistentAttribute | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDcInconsistentAttribute } | Should -Throw 'LDAP bind failed'

        }
    }
}
