BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-052.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdRodcRevealedPrivilegedAccount' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdRodcRevealedPrivilegedAccount {
        InModuleScope Maester { Test-MtAnssiAdRodcRevealedPrivilegedAccount }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-Account {
        param([string] $Name, [string[]] $Group = @('Domain Admins'))
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Kind              = 'User'
            Group             = $Group
            Link              = @('Member')
            Item              = [PSCustomObject]@{
                Name            = $Name
                SamAccountName  = $Name
                PasswordLastSet = [datetime]'2024-03-04'
            }
        }
    }

    function Get-Rodc {
        param([string] $Name, [string] $Type = 'ReadOnly')
        [PSCustomObject]@{ Type = $Type; Computer = [PSCustomObject]@{ Name = $Name } }
    }

    function Use-Ad {
        param(
            [object[]] $Account = @(),
            [object[]] $Controller = @(Get-Rodc -Name 'RODC1'),
            [object[]] $Revealed = @(),
            [object[]] $Unresolved = @(),
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3'
        )
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain            = [PSCustomObject]@{ DomainSID = $domainSidValue }
            Users             = @([PSCustomObject]@{ Name = 'U1' })
            Computers         = @([PSCustomObject]@{ Name = 'C1' })
            Groups            = @([PSCustomObject]@{ Name = 'G1' })
            DomainControllers = @([PSCustomObject]@{ Name = 'D1' })
            ProtocolEvidence  = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $controllers = $Controller
        Mock Get-MtAnssiAdDomainController -ModuleName Maester `
            -MockWith ({ $controllers }.GetNewClosure())
        $privileged = [PSCustomObject]@{ Account = $Account; Unresolved = $Unresolved }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $pairs = $Revealed
        Mock Get-MtAnssiAdRodcRevealedAccount -ModuleName Maester `
            -MockWith ({ $pairs }.GetNewClosure())
    }

    function Get-Pair {
        param([object] $Account, [string] $Rodc = 'RODC1')
        [PSCustomObject]@{ Account = $Account; Controller = (Get-Rodc -Name $Rodc) }
    }
}

Describe 'Test-MtAnssiAdRodcRevealedPrivilegedAccount' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when no privileged account is cached on an RODC' {
            Use-Ad -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob') `
                -Controller @(Get-Rodc -Name 'RODC1'; Get-Rodc -Name 'RODC2')

            Test-MtAnssiAdRodcRevealedPrivilegedAccount | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'None of the 2 privileged accounts is cached on the 2 read-only'
            }
        }

        It 'fails when a privileged account is cached on an RODC' {
            $alice = Get-Account -Name 'alice'
            Use-Ad -Account @($alice) -Revealed @(Get-Pair -Account $alice)

            Test-MtAnssiAdRodcRevealedPrivilegedAccount | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^1 privileged account secret\(s\) are cached' -and
                $Result -match '\| contoso\.com \|'
            }
        }

        It 'passes without reading anything when the domain has no RODC' {
            Use-Ad -Controller @(Get-Rodc -Name 'DC1' -Type 'Writable')

            Test-MtAnssiAdRodcRevealedPrivilegedAccount | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -eq 'The domain has no read-only domain controller.'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
            Should -Invoke Get-MtAnssiAdRodcRevealedAccount -ModuleName Maester -Times 0 -Exactly
        }
    }

    Context 'data read' {
        It 'reads the RODCs, the privileged accounts and their cached secrets' {
            $alice = Get-Account -Name 'alice'
            Use-Ad -Account @($alice) `
                -Controller @(Get-Rodc -Name 'DC1' -Type 'Writable'; Get-Rodc -Name 'RODC1')

            $null = Test-MtAnssiAdRodcRevealedPrivilegedAccount

            Should -Invoke Get-MtAnssiAdDomainController -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Computer)[0].Name -eq 'C1' -and @($DomainController)[0].Name -eq 'D1'
            }
            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'U1' -and
                @($Computer)[0].Name -eq 'C1' -and @($Group)[0].Name -eq 'G1' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdRodcRevealedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Controller).Count -eq 1 -and @($Controller)[0].Computer.Name -eq 'RODC1' -and
                @($Account)[0].Item.Name -eq 'alice' -and $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }

        It 'reads the Domain, Users, Computers, Groups and DomainControllers categories' {
            Use-Ad

            $null = Test-MtAnssiAdRodcRevealedPrivilegedAccount

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 5 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups' -and $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'result text' {
        It 'lists each account and RODC, sorted by account then RODC, with the password date' {
            $zed = Get-Account -Name 'zed' -Group 'Administrators', 'Domain Admins'
            $amy = Get-Account -Name 'amy'
            Use-Ad -Account @($zed, $amy) -Revealed @(
                Get-Pair -Account $zed -Rodc 'RODC1'
                Get-Pair -Account $amy -Rodc 'RODC2'
                Get-Pair -Account $amy -Rodc 'RODC1'
            )

            $null = Test-MtAnssiAdRodcRevealedPrivilegedAccount

            Should -Invoke @detail -ParameterFilter {
                $Result -match ('(?s)amy \| RODC1 \| Domain Admins \| 2024-03-04 \|.*' +
                    'amy \| RODC2 \|.*zed \| RODC1 \| Administrators, Domain Admins \|')
            }
        }

        It 'says how many members were not checked, on a pass and on a failure' -ForEach @(
            @{ Cached = $false }
            @{ Cached = $true }
        ) {
            $alice = Get-Account -Name 'alice'
            $pairs = @()
            if ($Cached) { $pairs = @(Get-Pair -Account $alice) }
            $unresolved = @([PSCustomObject]@{ DistinguishedName = 'CN=x'; Group = @('G') })
            Use-Ad -Account @($alice) -Revealed $pairs -Unresolved $unresolved

            $null = Test-MtAnssiAdRodcRevealedPrivilegedAccount

            Should -Invoke @detail -ParameterFilter { $Result -match 'also hold 1 member\(s\)' }
        }

        It 'escapes markdown in an account name' {
            $account = Get-Account -Name '[click](https://evil.example)|x'
            Use-Ad -Account @($account) -Revealed @(Get-Pair -Account $account)

            $null = Test-MtAnssiAdRodcRevealedPrivilegedAccount

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped without reading when the domain SID is missing' {
            Use-Ad -DomainSid $null

            Test-MtAnssiAdRodcRevealedPrivilegedAccount | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'lets the exception reach the engine when <Helper> fails' -ForEach @(
            @{ Helper = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Helper = 'Get-MtAnssiAdRodcRevealedAccount' }
        ) {
            Use-Ad
            Mock $Helper -ModuleName Maester -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdRodcRevealedPrivilegedAccount } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdRodcRevealedPrivilegedAccount } | Should -Throw 'LDAP bind failed'

        }
    }

    It 'is skipped when the <Collection> collection was not returned' -ForEach @(
        @{ Collection = 'Users' }
        @{ Collection = 'Computers' }
        @{ Collection = 'Groups' }
        @{ Collection = 'DomainControllers' }
    ) {
        $props = [ordered]@{ Users = @(); Computers = @(); Groups = @(); DomainControllers = @() }
        $props[$Collection] = $null
        $state = [PSCustomObject]$props
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

        Test-MtAnssiAdRodcRevealedPrivilegedAccount | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
