BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-065.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdRodcNeverRevealList' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdRodcNeverRevealList {
        InModuleScope Maester { Test-MtAnssiAdRodcNeverRevealList }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:groupSpec = @(
        @{ Name = 'Administrators'; Sid = 'S-1-5-32-544'; Container = 'CN=Builtin' }
        @{ Name = 'Server Operators'; Sid = 'S-1-5-32-549'; Container = 'CN=Builtin' }
        @{ Name = 'Account Operators'; Sid = 'S-1-5-32-548'; Container = 'CN=Builtin' }
        @{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551'; Container = 'CN=Builtin' }
        @{ Name = 'Denied RODC'; Sid = 'S-1-5-21-1-2-3-572'; Container = 'CN=Users' }
    )
    $script:groups = foreach ($spec in $script:groupSpec) {
        [PSCustomObject]@{
            DistinguishedName = "CN=$($spec.Name),$($spec.Container),DC=contoso,DC=com"
            Name              = $spec.Name
            Sid               = [PSCustomObject]@{ Value = $spec.Sid }
        }
    }
    $script:default = @($script:groups | ForEach-Object { $_.DistinguishedName })

    function Get-ComputerFixture {
        param(
            [string] $Name = 'RO1',
            [int] $PrimaryGroupId = 521,
            [AllowNull()] [string[]] $Never = $script:default,
            [switch] $NoProperty
        )
        $computer = [ordered]@{
            DistinguishedName = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            Name              = $Name
            PrimaryGroupId    = $PrimaryGroupId
            Sid               = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-3000' }
        }
        if (-not $NoProperty) { $computer['NeverRevealGroup'] = $Never }
        [PSCustomObject]$computer
    }

    function Use-Ad {
        param([object[]] $Computer = @(), [AllowNull()] [string] $DomainSid = $script:domainSid)
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain            = [PSCustomObject]@{ DomainSID = $domainSidValue }
            Computers         = $Computer
            Groups            = $script:groups
            DomainControllers = @()
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdRodcNeverRevealList' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when every RODC lists the default groups' {
            Use-Ad -Computer @((Get-ComputerFixture -Name 'RO1'), (Get-ComputerFixture -Name 'RO2'))

            Test-MtAnssiAdRodcNeverRevealList | Should -Be $true
        }

        It 'fails when an RODC misses a group' {
            Use-Ad -Computer @(Get-ComputerFixture -Never @($default | Select-Object -Skip 1))

            Test-MtAnssiAdRodcNeverRevealList | Should -Be $false
        }

        It 'passes when the domain has no RODC' {
            Use-Ad -Computer @(Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516 -Never @())

            Test-MtAnssiAdRodcNeverRevealList | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'no read-only domain controller'
            }
        }

        It 'ignores writable domain controllers and other computers' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'RO1')
                (Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516 -Never @())
                (Get-ComputerFixture -Name 'PC1' -PrimaryGroupId 515 -Never @())
            )

            Test-MtAnssiAdRodcNeverRevealList | Should -Be $true
        }
    }

    Context 'result text' {
        It 'counts the RODCs when the test passes' {
            Use-Ad -Computer @((Get-ComputerFixture -Name 'RO1'), (Get-ComputerFixture -Name 'RO2'))

            $null = Test-MtAnssiAdRodcNeverRevealList

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^The never-reveal lists of all 2 read-only domain controllers'
            }
        }

        It 'lists the RODCs by name with the missing groups' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'RO-Z' -Never @($default | Select-Object -First 4))
                (Get-ComputerFixture -Name 'RO-OK')
                (Get-ComputerFixture -Name 'RO-A' -Never @())
            )

            $null = Test-MtAnssiAdRodcNeverRevealList

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^2 of 3 read-only domain controllers' -and
                $text -match ('(?s)RO-A \| Administrators, Server Operators, Account Operators, ' +
                    'Backup Operators, Denied RODC Password Replication Group \|.*' +
                    'RO-Z \| Denied RODC Password Replication Group \|') -and
                $text -notmatch 'RO-OK'
            }
        }

        It 'escapes markdown in the RODC name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -Never @())

            $null = Test-MtAnssiAdRodcNeverRevealList

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Domain, Computers, Groups and DomainControllers categories' {
            Use-Ad -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdRodcNeverRevealList

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Computers' -and
                $Categories -contains 'Groups' -and $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the domain SID is missing' {
            Use-Ad -Computer @(Get-ComputerFixture) -DomainSid $null

            Test-MtAnssiAdRodcNeverRevealList | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'is skipped when the computers do not carry the RODC attributes' {
            Use-Ad -Computer @(Get-ComputerFixture -NoProperty)

            Test-MtAnssiAdRodcNeverRevealList | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdRodcNeverRevealList } | Should -Throw 'LDAP bind failed'

        }
    }
}
