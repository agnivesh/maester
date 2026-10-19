BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-010.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDelegationProtocolTransition' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDelegationProtocolTransition {
        InModuleScope Maester { Test-MtAnssiAdDelegationProtocolTransition }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-ControllerFixture {
        param([string] $Name = 'DC1', [int] $PrimaryGroupId = 516, [switch] $NoProperty)
        $computer = [ordered]@{
            DistinguishedName          = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            Name                       = $Name
            DnsHostName                = "$($Name.ToLowerInvariant()).contoso.com"
            PrimaryGroupId             = $PrimaryGroupId
            Enabled                    = $true
            TrustedToAuthForDelegation = $false
        }
        if (-not $NoProperty) { $computer['AllowedToDelegateTo'] = [string[]]@() }
        [PSCustomObject]$computer
    }

    function Get-AccountFixture {
        param([string] $Name = 'svc', [string[]] $Target = @('cifs/dc1.contoso.com'),
            [bool] $Transition = $true, [bool] $Enabled = $true)
        [PSCustomObject]@{
            DistinguishedName          = "CN=$Name,OU=Service,DC=contoso,DC=com"
            Name                       = $Name
            Enabled                    = $Enabled
            TrustedToAuthForDelegation = $Transition
            AllowedToDelegateTo        = $Target
        }
    }

    function Use-Ad {
        param([object[]] $User = @(), [object[]] $Computer = @(Get-ControllerFixture))
        $state = [PSCustomObject]@{ Users = $User; Computers = $Computer; DomainControllers = @() }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDelegationProtocolTransition' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'fails for a user that delegates to a domain controller' {
            Use-Ad -User @(Get-AccountFixture)

            Test-MtAnssiAdDelegationProtocolTransition | Should -Be $false
        }

        It 'fails for a computer that delegates to krbtgt' {
            $app = Get-AccountFixture -Name 'APP1$' -Target @('krbtgt/CONTOSO.COM')
            Use-Ad -Computer @((Get-ControllerFixture), $app)

            Test-MtAnssiAdDelegationProtocolTransition | Should -Be $false
        }

        It 'passes when the account belongs to the other test' {
            Use-Ad -User @(Get-AccountFixture -Transition $false)

            Test-MtAnssiAdDelegationProtocolTransition | Should -Be $true
        }

        It 'passes for delegation to an ordinary server' {
            Use-Ad -User @(Get-AccountFixture -Target @('cifs/app1.contoso.com'))

            Test-MtAnssiAdDelegationProtocolTransition | Should -Be $true
        }

        It 'passes for a disabled account' {
            Use-Ad -User @(Get-AccountFixture -Enabled $false)

            Test-MtAnssiAdDelegationProtocolTransition | Should -Be $true
        }

        It 'recognizes a read-only domain controller by its short name' {
            Use-Ad -User @(Get-AccountFixture -Target @('HOST/RO1')) -Computer @(
                (Get-ControllerFixture -Name 'DC1')
                (Get-ControllerFixture -Name 'RO1' -PrimaryGroupId 521)
            )

            Test-MtAnssiAdDelegationProtocolTransition | Should -Be $false
        }
    }

    Context 'result text' {
        It 'says so when no account has this delegation' {
            Use-Ad -User @(Get-AccountFixture -Target @('cifs/app1'))

            $null = Test-MtAnssiAdDelegationProtocolTransition

            Should -Invoke @detail -ParameterFilter {
                $Result -match ('^No enabled account has ' +
                    'constrained delegation with protocol transition to a domain controller')
            }
        }

        It 'lists the accounts by name with their type and privileged targets' {
            $targets = @('cifs/app2', 'ldap/DC1', 'HOST/dc1.contoso.com')
            $app = Get-AccountFixture -Name 'ZAPP$' -Target $targets
            Use-Ad -User @(
                (Get-AccountFixture -Name 'abe' -Target @('cifs/dc1.contoso.com', 'http/web'))
                (Get-AccountFixture -Name 'other' -Transition $false)
            ) -Computer @((Get-ControllerFixture), $app)

            $null = Test-MtAnssiAdDelegationProtocolTransition

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match ('^2 enabled account\(s\) have ' +
                    'constrained delegation with protocol transition to a domain controller') -and
                $text -match ('(?s)abe \| User \| cifs/dc1\.contoso\.com \|.*' +
                    'ZAPP\$ \| Computer \| ldap/DC1, HOST/dc1\.contoso\.com \|') -and
                $text -notmatch '\| other \|' -and $text -notmatch 'http/web'
            }
        }

        It 'escapes markdown in the account name' {
            Use-Ad -User @(Get-AccountFixture -Name '[click](https://evil.example)|x')

            $null = Test-MtAnssiAdDelegationProtocolTransition

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Users, Computers and DomainControllers categories' {
            Use-Ad

            $null = Test-MtAnssiAdDelegationProtocolTransition

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 3 -and $Categories -contains 'Users' -and
                $Categories -contains 'Computers' -and $Categories -contains 'DomainControllers'
            }
        }

        It 'finds a domain controller through its directory entry' {
            $dc = Get-ControllerFixture -Name 'DC9' -PrimaryGroupId 515
            $entry = [PSCustomObject]@{ ServerReference = $dc.DistinguishedName }
            $state = [PSCustomObject]@{
                Users             = @(Get-AccountFixture -Target @('cifs/DC9'))
                Computers         = @($dc)
                DomainControllers = @($entry)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDelegationProtocolTransition | Should -Be $false
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no domain controller is found' {
            Use-Ad -User @(Get-AccountFixture) `
                -Computer @(Get-ControllerFixture -PrimaryGroupId 515)

            Test-MtAnssiAdDelegationProtocolTransition | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain controller'
            }
        }

        It 'is skipped when the computers do not carry the delegation targets' {
            Use-Ad -User @(Get-AccountFixture) -Computer @(Get-ControllerFixture -NoProperty)

            Test-MtAnssiAdDelegationProtocolTransition | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDelegationProtocolTransition } | Should -Throw 'LDAP bind failed'

        }
    }
}
