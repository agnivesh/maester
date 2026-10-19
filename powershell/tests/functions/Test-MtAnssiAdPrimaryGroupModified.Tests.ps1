BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-061.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrimaryGroupModified' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrimaryGroupModified {
        InModuleScope Maester { Test-MtAnssiAdPrimaryGroupModified }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-UserFixture {
        param([string] $Name = 'alice', [object] $Group = 513, [bool] $Enabled = $true)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,OU=Users,DC=contoso,DC=com"
            Name              = $Name
            Enabled           = $Enabled
            PrimaryGroupId    = $Group
        }
    }

    function Get-ComputerFixture {
        param([string] $Name = 'PC1$', [object] $Group = 515, [object] $Uac = 4096)
        [PSCustomObject]@{
            DistinguishedName  = "CN=$Name,CN=Computers,DC=contoso,DC=com"
            Name               = $Name
            Enabled            = $true
            PrimaryGroupId     = $Group
            UserAccountControl = $Uac
        }
    }

    function Use-Ad {
        param([AllowNull()] [object[]] $User = @(), [AllowNull()] [object[]] $Computer = @())
        $state = [PSCustomObject]@{ Users = $User; Computers = $Computer }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdPrimaryGroupModified' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when every account has the default primary group' {
            Use-Ad -User @(Get-UserFixture) -Computer @(Get-ComputerFixture)

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $true
        }

        It 'fails for a user in a privileged primary group' {
            Use-Ad -User @(Get-UserFixture -Group 512) -Computer @(Get-ComputerFixture)

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $false
        }

        It 'fails for a computer whose primary group is Domain Admins' {
            Use-Ad -User @(Get-UserFixture) -Computer @(Get-ComputerFixture -Group 512)

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $false
        }

        It 'fails for a disabled account' {
            Use-Ad -User @(Get-UserFixture -Group 512 -Enabled $false)

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $false
        }

        It 'fails for a group ID below 1000' {
            Use-Ad -User @(Get-UserFixture -Group 999)

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $false
        }

        It 'fails for a custom group, whatever its ID' {
            Use-Ad -User @(Get-UserFixture -Group 1000)

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $false
        }

        It 'fails for Domain Computers as the primary group of a user' {
            Use-Ad -User @(Get-UserFixture -Group 515)

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $false
        }

        It 'passes for the Domain Guests group of a user' {
            Use-Ad -User @(Get-UserFixture -Name 'guest' -Group 514)

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $true
        }

        It 'accepts the defaults of domain controllers and read-only domain controllers' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'DC1$' -Group 516 -Uac 532480)
                (Get-ComputerFixture -Name 'RO1$' -Group 521 -Uac 83890176)
            )

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $true
        }

        It 'fails for a member server in the Domain Controllers group' {
            Use-Ad -Computer @(Get-ComputerFixture -Group 516 -Uac 4096)

            Test-MtAnssiAdPrimaryGroupModified | Should -Be $false
        }
    }

    Context 'result text' {
        It 'counts the checked accounts when the test passes' {
            Use-Ad -User @(Get-UserFixture -Name 'a'; Get-UserFixture -Name 'b') `
                -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdPrimaryGroupModified

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 3 user and computer accounts have the default'
            }
        }

        It 'lists the accounts worst group first, then by name, with their details' {
            Use-Ad -User @(
                (Get-UserFixture -Name 'zed' -Group 512)
                (Get-UserFixture -Name 'ok' -Group 513)
                (Get-UserFixture -Name 'abe' -Group 519 -Enabled $false)
                (Get-UserFixture -Name 'bob' -Group 512)
                (Get-UserFixture -Name 'cust' -Group 1105)
            ) -Computer @(Get-ComputerFixture -Name 'SRV$' -Group 516)

            $null = Test-MtAnssiAdPrimaryGroupModified

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^5 of 6 user and computer accounts' -and
                $text -match ('(?s)bob \| User \| True \| 512 \| 513 or 514 \|.*' +
                    'zed \| User \| True \| 512 \|.*SRV\$ \| Computer \| True \| 516 \| 515 \|.*' +
                    'abe \| User \| False \| 519 \|.*cust \| User \| True \| 1105 \|') -and
                $text -notmatch '\| ok \|'
            }
        }

        It 'escapes markdown in the account name' {
            Use-Ad -User @(Get-UserFixture -Name '[click](https://evil.example)|x' -Group 512)

            $null = Test-MtAnssiAdPrimaryGroupModified

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Users and Computers categories' {
            Use-Ad -User @(Get-UserFixture)

            $null = Test-MtAnssiAdPrimaryGroupModified

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Users' -and
                $Categories -contains 'Computers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no account has a primary group ID' {
            Use-Ad -User @(Get-UserFixture -Group $null) `
                -Computer @(Get-ComputerFixture -Group $null)

            Test-MtAnssiAdPrimaryGroupModified | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'primary group ID'
            }
        }

        It 'is skipped when there are no accounts' {
            Use-Ad -User @() -Computer @()

            Test-MtAnssiAdPrimaryGroupModified | Should -BeNullOrEmpty
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdPrimaryGroupModified } | Should -Throw 'LDAP bind failed'

        }
    }
}
