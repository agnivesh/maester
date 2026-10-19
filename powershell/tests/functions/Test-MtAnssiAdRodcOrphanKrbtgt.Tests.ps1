BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-069.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdRodcOrphanKrbtgt' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdRodcOrphanKrbtgt {
        InModuleScope Maester { Test-MtAnssiAdRodcOrphanKrbtgt }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-UserFixture {
        param(
            [string] $Sam = 'krbtgt_12345',
            [object] $Created = [datetime]'2024-05-06',
            [object] $LastSet = [datetime]'2024-05-07'
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Sam,CN=Users,DC=contoso,DC=com"
            Name              = $Sam
            SamAccountName    = $Sam
            Enabled           = $false
            Created           = $Created
            PasswordLastSet   = $LastSet
        }
    }

    function Get-ComputerFixture {
        param([string] $Name = 'RODC1$', [AllowNull()] [string] $Link = $null, [switch] $NoProperty)
        $computer = [ordered]@{ Name = $Name }
        if (-not $NoProperty) { $computer['KrbTgtLink'] = $Link }
        [PSCustomObject]$computer
    }

    function Use-Ad {
        param([AllowNull()] [object[]] $User = @(), [AllowNull()] [object[]] $Computer = @())
        $state = [PSCustomObject]@{ Users = $User; Computers = $Computer }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdRodcOrphanKrbtgt' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when every krbtgt_ account is linked to a computer' {
            $user = Get-UserFixture -Sam 'krbtgt_1'
            Use-Ad -User @($user, (Get-UserFixture -Sam 'krbtgt')) -Computer @(
                Get-ComputerFixture -Link $user.DistinguishedName)

            Test-MtAnssiAdRodcOrphanKrbtgt | Should -Be $true
        }

        It 'passes when the domain has no krbtgt_ account' {
            Use-Ad -User @(Get-UserFixture -Sam 'krbtgt') -Computer @(Get-ComputerFixture)

            Test-MtAnssiAdRodcOrphanKrbtgt | Should -Be $true
        }

        It 'fails when a krbtgt_ account is not linked' {
            Use-Ad -User @(Get-UserFixture -Sam 'krbtgt_1') -Computer @(Get-ComputerFixture)

            Test-MtAnssiAdRodcOrphanKrbtgt | Should -Be $false
        }

        It 'fails when only one of two accounts is an orphan' {
            $linked = Get-UserFixture -Sam 'krbtgt_1'
            Use-Ad -User @($linked, (Get-UserFixture -Sam 'krbtgt_2')) -Computer @(
                Get-ComputerFixture -Link $linked.DistinguishedName)

            Test-MtAnssiAdRodcOrphanKrbtgt | Should -Be $false
        }
    }

    Context 'result text' {
        It 'counts the accounts when the test passes' {
            $first = Get-UserFixture -Sam 'krbtgt_1'
            $second = Get-UserFixture -Sam 'krbtgt_2'
            Use-Ad -User @($first, $second) -Computer @(
                (Get-ComputerFixture -Name 'R1$' -Link $first.DistinguishedName)
                (Get-ComputerFixture -Name 'R2$' -Link $second.DistinguishedName)
            )

            $null = Test-MtAnssiAdRodcOrphanKrbtgt

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^All 2 krbtgt_\* accounts belong to a read-only domain controller'
            }
        }

        It 'lists only the orphans by name with their dates' {
            $linked = Get-UserFixture -Sam 'krbtgt_9'
            Use-Ad -User @(
                (Get-UserFixture -Sam 'krbtgt_30' -Created ([datetime]'2021-01-02') `
                    -LastSet $null)
                $linked
                (Get-UserFixture -Sam 'krbtgt_10' -Created ([datetime]'2024-03-04') `
                    -LastSet ([datetime]'2024-03-05'))
            ) -Computer @(Get-ComputerFixture -Link $linked.DistinguishedName)

            $null = Test-MtAnssiAdRodcOrphanKrbtgt

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^2 of 3 krbtgt_\* accounts are not linked' -and
                $text -match ('(?s)krbtgt_10 \| False \| 2024-03-04 \| 2024-03-05 \|.*' +
                    'krbtgt_30 \| False \| 2021-01-02 \| Never \|') -and
                $text -notmatch 'krbtgt_9'
            }
        }

        It 'escapes markdown in the account name' {
            Use-Ad -User @(Get-UserFixture -Sam 'krbtgt_[click](https://evil.example)|x')

            $null = Test-MtAnssiAdRodcOrphanKrbtgt

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Users and Computers categories' {
            Use-Ad -User @(Get-UserFixture) -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdRodcOrphanKrbtgt

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Users' -and
                $Categories -contains 'Computers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when there are no users' {
            Use-Ad -User @() -Computer @(Get-ComputerFixture)

            Test-MtAnssiAdRodcOrphanKrbtgt | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'msDS-KrbTgtLink'
            }
        }

        It 'is skipped when the computers do not carry the attribute' {
            Use-Ad -User @(Get-UserFixture) -Computer @(Get-ComputerFixture -NoProperty)

            Test-MtAnssiAdRodcOrphanKrbtgt | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'is skipped when there are no computers' {
            Use-Ad -User @(Get-UserFixture) -Computer @()

            Test-MtAnssiAdRodcOrphanKrbtgt | Should -BeNullOrEmpty
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdRodcOrphanKrbtgt } | Should -Throw 'LDAP bind failed'

        }
    }
}
