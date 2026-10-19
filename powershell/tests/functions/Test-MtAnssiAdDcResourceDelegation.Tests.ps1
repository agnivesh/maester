BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-009.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDcResourceDelegation' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDcResourceDelegation {
        InModuleScope Maester { Test-MtAnssiAdDcResourceDelegation }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    $script:appSid = 'S-1-5-21-1-2-3-1105'
    $script:users = @([PSCustomObject]@{
            DistinguishedName = 'CN=svc,OU=Service,DC=contoso,DC=com'; Name = 'svc'
            Sid               = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1201' }
        })

    function Get-ComputerFixture {
        param(
            [string] $Name = 'DC1',
            [int] $PrimaryGroupId = 516,
            [AllowNull()] [object] $Allowed = $null,
            [switch] $NoProperty
        )
        $computer = [ordered]@{
            DistinguishedName = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            Name              = $Name
            PrimaryGroupId    = $PrimaryGroupId
            Sid               = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1105' }
        }
        if (-not $NoProperty) { $computer['AllowedToActOnBehalfOfOtherIdentity'] = $Allowed }
        [PSCustomObject]$computer
    }

    function Use-Ad {
        param([object[]] $Computer = @(Get-ComputerFixture), [object[]] $Entry = @())
        $state = [PSCustomObject]@{
            Users = $script:users; Computers = $Computer; Groups = @(); DomainControllers = $Entry
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDcResourceDelegation' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when no domain controller has the attribute' {
            Use-Ad -Computer @((Get-ComputerFixture -Name 'DC1'), (Get-ComputerFixture -Name 'DC2'))

            Test-MtAnssiAdDcResourceDelegation | Should -Be $true
        }

        It 'fails when a domain controller allows an account' {
            Use-Ad -Computer @(Get-ComputerFixture -Allowed ([string[]]@('S-1-5-21-1-2-3-1201')))

            Test-MtAnssiAdDcResourceDelegation | Should -Be $false
        }

        It 'fails when the attribute is set but allows nothing readable' {
            Use-Ad -Computer @(Get-ComputerFixture -Allowed ([string[]]@()))

            Test-MtAnssiAdDcResourceDelegation | Should -Be $false
        }

        It 'checks read-only domain controllers' {
            $rodc = Get-ComputerFixture -Name 'RO1' -PrimaryGroupId 521 `
                -Allowed ([string[]]@('S-1-5-21-1-2-3-1201'))
            Use-Ad -Computer @((Get-ComputerFixture), $rodc)

            Test-MtAnssiAdDcResourceDelegation | Should -Be $false
        }

        It 'ignores other computers with the attribute' {
            $server = Get-ComputerFixture -Name 'APP1' -PrimaryGroupId 515 `
                -Allowed ([string[]]@('S-1-5-21-1-2-3-1201'))
            Use-Ad -Computer @((Get-ComputerFixture), $server)

            Test-MtAnssiAdDcResourceDelegation | Should -Be $true
        }

        It 'finds a domain controller through its directory entry' {
            $dc = Get-ComputerFixture -Name 'DC9' -PrimaryGroupId 515 `
                -Allowed ([string[]]@('S-1-5-21-1-2-3-1201'))
            $entry = [PSCustomObject]@{ ServerReference = $dc.DistinguishedName }
            Use-Ad -Computer @($dc) -Entry @($entry)

            Test-MtAnssiAdDcResourceDelegation | Should -Be $false
        }
    }

    Context 'result text' {
        It 'counts the domain controllers when the test passes' {
            Use-Ad -Computer @((Get-ComputerFixture -Name 'DC1'), (Get-ComputerFixture -Name 'DC2'))

            $null = Test-MtAnssiAdDcResourceDelegation

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^None of the 2 domain controllers allows resource-based'
            }
        }

        It 'lists the domain controllers by name with the accounts they allow' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'DC-Z' -Allowed ([string[]]@('S-1-5-21-9-9-9-1500')))
                (Get-ComputerFixture -Name 'DC-OK')
                (Get-ComputerFixture -Name 'DC-A' `
                    -Allowed ([string[]]@('S-1-5-21-1-2-3-1201', 'S-1-5-21-9-9-9-1600')))
            )

            $null = Test-MtAnssiAdDcResourceDelegation

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^2 of 3 domain controllers allow resource-based' -and
                $text -match ('(?s)DC-A \| Writable \| svc \(S-1-5-21-1-2-3-1201\), ' +
                    'S-1-5-21-9-9-9-1600 \|.*' +
                    'DC-Z \| Writable \| S-1-5-21-9-9-9-1500 \|') -and
                $text -notmatch 'DC-OK'
            }
        }

        It 'escapes markdown in the controller name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -Allowed ([string[]]@()))

            $null = Test-MtAnssiAdDcResourceDelegation

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Users, Computers, Groups and DomainControllers categories' {
            Use-Ad

            $null = Test-MtAnssiAdDcResourceDelegation

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Users' -and
                $Categories -contains 'Computers' -and $Categories -contains 'Groups' -and
                $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no domain controller is found' {
            Use-Ad -Computer @(Get-ComputerFixture -PrimaryGroupId 515)

            Test-MtAnssiAdDcResourceDelegation | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain controller'
            }
        }

        It 'is skipped when the computers do not carry the attribute' {
            Use-Ad -Computer @(Get-ComputerFixture -NoProperty)

            Test-MtAnssiAdDcResourceDelegation | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDcResourceDelegation } | Should -Throw 'LDAP bind failed'

        }
    }
}
