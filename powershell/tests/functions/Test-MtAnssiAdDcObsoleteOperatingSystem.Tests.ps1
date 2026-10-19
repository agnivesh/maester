BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-007.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDcObsoleteOperatingSystem' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDcObsoleteOperatingSystem {
        InModuleScope Maester { Test-MtAnssiAdDcObsoleteOperatingSystem }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-ControllerFixture {
        param(
            [string] $Name = 'DC1',
            [AllowEmptyString()] [string] $OperatingSystem = 'Windows Server 2022 Standard',
            [int] $PrimaryGroupId = 516
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            Name              = $Name
            OperatingSystem   = $OperatingSystem
            PrimaryGroupId    = $PrimaryGroupId
        }
    }

    function Use-Ad {
        param([object[]] $Computer)
        $state = [PSCustomObject]@{ Computers = $Computer; DomainControllers = @() }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDcObsoleteOperatingSystem' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails for Windows Server 2012 R2'
                OperatingSystem = 'Windows Server 2012 R2 Standard'; Expected = $false }
            @{ Name = 'fails for Windows Server 2008 with the trademark sign'
                OperatingSystem = 'Windows Server(R) 2008 Enterprise'; Expected = $false }
            @{ Name = 'fails for Windows Server 2003'
                OperatingSystem = 'Windows Server 2003'; Expected = $false }
            @{ Name = 'passes for Windows Server 2022'
                OperatingSystem = 'Windows Server 2022 Datacenter'; Expected = $true }
            @{ Name = 'passes for Windows Server 2025'
                OperatingSystem = 'Windows Server 2025 Standard'; Expected = $true }
            @{ Name = 'passes for an unknown operating system'
                OperatingSystem = 'Windows Server Datacenter'; Expected = $true }
            @{ Name = 'passes for an empty operating system'
                OperatingSystem = ''; Expected = $true }
        ) {
            Use-Ad -Computer @(Get-ControllerFixture -OperatingSystem $OperatingSystem)

            Test-MtAnssiAdDcObsoleteOperatingSystem | Should -Be $Expected
        }

        It 'fails when one of several controllers is obsolete' {
            Use-Ad -Computer @(
                Get-ControllerFixture -Name 'NEW1'
                Get-ControllerFixture -Name 'OLD1' -OperatingSystem 'Windows Server 2012'
                Get-ControllerFixture -Name 'NEW2'
            )

            Test-MtAnssiAdDcObsoleteOperatingSystem | Should -Be $false
        }

        It 'ignores computers that are not domain controllers' {
            Use-Ad -Computer @(
                Get-ControllerFixture -Name 'DC1'
                Get-ControllerFixture -Name 'OLDFILE' -OperatingSystem 'Windows Server 2008' `
                    -PrimaryGroupId 515
            )

            Test-MtAnssiAdDcObsoleteOperatingSystem | Should -BeTrue
        }

        It 'evaluates read-only domain controllers' {
            Use-Ad -Computer @(
                Get-ControllerFixture -Name 'RO1' -OperatingSystem 'Windows Server 2012 R2' `
                    -PrimaryGroupId 521
            )

            Test-MtAnssiAdDcObsoleteOperatingSystem | Should -Be $false
        }
    }

    Context 'the end of support is compared with today' {
        It 'passes Windows Server 2016 on its last day of support' {
            Mock Get-Date -ModuleName Maester { [datetime]::new(2027, 1, 12, 15, 0, 0) }
            Use-Ad -Computer @(Get-ControllerFixture -OperatingSystem 'Windows Server 2016')

            Test-MtAnssiAdDcObsoleteOperatingSystem | Should -BeTrue
        }

        It 'fails Windows Server 2016 the day after' {
            Mock Get-Date -ModuleName Maester { [datetime]::new(2027, 1, 13, 1, 0, 0) }
            Use-Ad -Computer @(Get-ControllerFixture -OperatingSystem 'Windows Server 2016')

            Test-MtAnssiAdDcObsoleteOperatingSystem | Should -Be $false
        }
    }

    Context 'result text' {
        It 'counts the controllers when the test passes' {
            Use-Ad -Computer @(Get-ControllerFixture -Name 'A'; Get-ControllerFixture -Name 'B')

            $null = Test-MtAnssiAdDcObsoleteOperatingSystem

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^None of the 2 domain controllers runs an obsolete operating'
            }
        }

        It 'lists the obsolete controllers with type, system and end date, oldest first' {
            Use-Ad -Computer @(
                Get-ControllerFixture -Name 'MID' -OperatingSystem 'Windows Server 2012 R2'
                Get-ControllerFixture -Name 'OLDEST' -OperatingSystem 'Windows Server 2003'
                Get-ControllerFixture -Name 'RO1' -OperatingSystem 'Windows Server 2008 R2' `
                    -PrimaryGroupId 521
                Get-ControllerFixture -Name 'FINE'
            )

            $null = Test-MtAnssiAdDcObsoleteOperatingSystem

            Should -Invoke @detail -ParameterFilter {
                $Result -match '3 of 4 domain controllers' -and
                $Result -match '(?s)OLDEST \| Writable \| Windows Server 2003 \| 2015-07-14 \|.*' +
                'RO1 \| ReadOnly \| Windows Server 2008 R2 \| 2020-01-14 \|.*' +
                'MID \| Writable \| Windows Server 2012 R2 \| 2023-10-10 \|' -and
                $Result -notmatch 'FINE'
            }
        }

        It 'mentions controllers whose operating system is unknown, passing or failing' {
            Use-Ad -Computer @(
                Get-ControllerFixture -Name 'OLD' -OperatingSystem 'Windows Server 2008'
                Get-ControllerFixture -Name 'MYSTERY' -OperatingSystem ''
            )

            $null = Test-MtAnssiAdDcObsoleteOperatingSystem

            Should -Invoke @detail -ParameterFilter {
                $Result -match '1 domain controller\(s\) have an empty or unrecognized'
            }
        }

        It 'mentions unknown operating systems when the test passes' {
            Use-Ad -Computer @(Get-ControllerFixture -OperatingSystem 'Windows Server Standard')

            $null = Test-MtAnssiAdDcObsoleteOperatingSystem

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'None of the 1 domain controllers' -and
                $Result -match '1 domain controller\(s\) have an empty or unrecognized'
            }
        }

        It 'does not mention unknown operating systems when all are known' {
            Use-Ad -Computer @(Get-ControllerFixture)

            $null = Test-MtAnssiAdDcObsoleteOperatingSystem

            Should -Invoke @detail -ParameterFilter { $Result -notmatch 'unrecognized' }
        }

        It 'escapes markdown in the controller name and operating system' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(
                Get-ControllerFixture -Name $evil -OperatingSystem 'Windows Server 2008 [a](b)'
            )

            $null = Test-MtAnssiAdDcObsoleteOperatingSystem

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('[a](b)')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers and DomainControllers categories' {
            Use-Ad -Computer @(Get-ControllerFixture)

            $null = Test-MtAnssiAdDcObsoleteOperatingSystem

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Computers' -and
                $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no domain controller computer account is found' {
            Use-Ad -Computer @(Get-ControllerFixture -PrimaryGroupId 515)

            Test-MtAnssiAdDcObsoleteOperatingSystem | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain controller'
            }
        }

        It 'is skipped when there is no computer data' {
            Use-Ad -Computer $null

            Test-MtAnssiAdDcObsoleteOperatingSystem | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDcObsoleteOperatingSystem } | Should -Throw 'LDAP bind failed'

        }
    }
}
