BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-066.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdRodcRevealList' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdRodcRevealList {
        InModuleScope Maester { Test-MtAnssiAdRodcRevealList }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:groupSpec = @(
        @{ Name = 'Allowed RODC'; Rid = 571 }
        @{ Name = 'Domain Admins'; Rid = 512 }
        @{ Name = 'Branch Users'; Rid = 1104 }
    )
    $script:groups = foreach ($spec in $script:groupSpec) {
        [PSCustomObject]@{
            DistinguishedName = "CN=$($spec.Name),CN=Users,DC=contoso,DC=com"
            Name              = $spec.Name
            Sid               = [PSCustomObject]@{ Value = "S-1-5-21-1-2-3-$($spec.Rid)" }
        }
    }
    $script:allowedDn = 'CN=Allowed RODC,CN=Users,DC=contoso,DC=com'
    $script:adminsDn = 'CN=Domain Admins,CN=Users,DC=contoso,DC=com'
    $script:branchDn = 'CN=Branch Users,CN=Users,DC=contoso,DC=com'

    function Get-ComputerFixture {
        param(
            [string] $Name = 'RO1',
            [int] $PrimaryGroupId = 521,
            [AllowNull()] [string[]] $Reveal = @($script:allowedDn),
            [switch] $NoProperty
        )
        $computer = [ordered]@{
            DistinguishedName = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            Name              = $Name
            PrimaryGroupId    = $PrimaryGroupId
            Sid               = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-3000' }
        }
        if (-not $NoProperty) { $computer['RevealOnDemandGroup'] = $Reveal }
        [PSCustomObject]$computer
    }

    $script:administratorDn = 'CN=Administrator,CN=Users,DC=contoso,DC=com'
    $script:users = @([PSCustomObject]@{
            DistinguishedName = $script:administratorDn
            Name              = 'Administrator'
            Sid               = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-500' }
        })

    function Use-Ad {
        param([object[]] $Computer = @(), [AllowNull()] [string] $DomainSid = $script:domainSid)
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain            = [PSCustomObject]@{ DomainSID = $domainSidValue }
            Users             = $script:users
            Computers         = $Computer
            Groups            = $script:groups
            DomainControllers = @()
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdRodcRevealList' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes with the default entry and a custom group' {
            Use-Ad -Computer @(Get-ComputerFixture -Reveal @($allowedDn, $branchDn))

            Test-MtAnssiAdRodcRevealList | Should -Be $true
        }

        It 'fails when an RODC may cache a privileged group' {
            Use-Ad -Computer @(Get-ComputerFixture -Reveal @($allowedDn, $adminsDn))

            Test-MtAnssiAdRodcRevealList | Should -Be $false
        }

        It 'passes when the domain has no RODC' {
            $writable = Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516 -Reveal @($adminsDn)
            Use-Ad -Computer @($writable)

            Test-MtAnssiAdRodcRevealList | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'no read-only domain controller'
            }
        }

        It 'ignores writable domain controllers' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'RO1')
                (Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516 -Reveal @($adminsDn))
            )

            Test-MtAnssiAdRodcRevealList | Should -Be $true
        }

        It 'passes when the only other entry is outside the collected data' {
            Use-Ad -Computer @(Get-ComputerFixture -Reveal @($allowedDn, 'CN=X,DC=other,DC=com'))

            Test-MtAnssiAdRodcRevealList | Should -Be $true
        }
    }

    Context 'result text' {
        It 'counts the RODCs when the test passes' {
            Use-Ad -Computer @((Get-ComputerFixture -Name 'RO1'), (Get-ComputerFixture -Name 'RO2'))

            $null = Test-MtAnssiAdRodcRevealList

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^The reveal lists of all 2 read-only domain controllers' -and
                $Result -notmatch 'outside the collected data'
            }
        }

        It 'mentions the entries it could not resolve' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'RO1' -Reveal @('CN=X,DC=other,DC=com'))
                (Get-ComputerFixture -Name 'RO2' -Reveal @('CN=Y,DC=other,DC=com', $adminsDn))
            )

            $null = Test-MtAnssiAdRodcRevealList

            Should -Invoke @detail -ParameterFilter {
                $Result -match '2 entries point outside the collected data'
            }
        }

        It 'lists the RODCs by name with their privileged entries' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'RO-Z' -Reveal @($adminsDn))
                (Get-ComputerFixture -Name 'RO-OK')
                (Get-ComputerFixture -Name 'RO-A' -Reveal @($allowedDn, $adminsDn))
            )

            $null = Test-MtAnssiAdRodcRevealList

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^2 of 3 read-only domain controllers may cache' -and
                $text -match ('(?s)RO-A \| Domain Admins \(S-1-5-21-1-2-3-512\) \|.*' +
                    'RO-Z \| Domain Admins \(S-1-5-21-1-2-3-512\) \|') -and
                $text -notmatch 'RO-OK'
            }
        }

        It 'lists every privileged entry of an RODC, users included' {
            Use-Ad -Computer @(Get-ComputerFixture -Reveal @($adminsDn, $administratorDn))

            Test-MtAnssiAdRodcRevealList | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match ('RO1 \| Domain Admins \(S-1-5-21-1-2-3-512\), ' +
                    'Administrator \(S-1-5-21-1-2-3-500\) \|')
            }
        }

        It 'escapes markdown in the RODC name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -Reveal @($adminsDn))

            $null = Test-MtAnssiAdRodcRevealList

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Domain, Users, Computers, Groups and DomainControllers categories' {
            Use-Ad -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdRodcRevealList

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 5 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups' -and $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the domain SID is missing' {
            Use-Ad -Computer @(Get-ComputerFixture) -DomainSid $null

            Test-MtAnssiAdRodcRevealList | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'is skipped when the computers do not carry the RODC attributes' {
            Use-Ad -Computer @(Get-ComputerFixture -NoProperty)

            Test-MtAnssiAdRodcRevealList | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdRodcRevealList } | Should -Throw 'LDAP bind failed'

        }
    }
}
