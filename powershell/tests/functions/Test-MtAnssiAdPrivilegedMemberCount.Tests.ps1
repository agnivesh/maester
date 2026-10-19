BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-032.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrivilegedMemberCount' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrivilegedMemberCount {
        InModuleScope Maester { Test-MtAnssiAdPrivilegedMemberCount }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-Account {
        param(
            [string] $Name,
            [string] $Kind = 'User',
            [string] $Rid = '2000',
            [string[]] $Group = @('Domain Admins')
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Kind              = $Kind
            Group             = $Group
            Link              = @('Member')
            Item              = [PSCustomObject]@{
                Name           = $Name
                SamAccountName = $Name
                Enabled        = $true
                Sid            = [PSCustomObject]@{ Value = "S-1-5-21-1-2-3-$Rid" }
            }
        }
    }

    function Get-Population {
        param([int] $Count)
        for ($i = 1; $i -le $Count; $i++) { Get-Account -Name "admin$i" -Rid "$(3000 + $i)" }
    }

    function Use-Ad {
        param(
            [object[]] $Account = @(),
            [object[]] $Controller = @(),
            [AllowNull()] [object] $DomainCount = 1,
            [object[]] $Unresolved = @(),
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3'
        )
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain            = [PSCustomObject]@{
                DomainSID = $domainSidValue; ForestDomainCount = $DomainCount
            }
            Users             = @([PSCustomObject]@{ Name = 'U1' })
            Computers         = @([PSCustomObject]@{ Name = 'C1' })
            Groups            = @([PSCustomObject]@{ Name = 'G1' })
            DomainControllers = @([PSCustomObject]@{ Name = 'D1' })
            ProtocolEvidence  = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{ Account = $Account; Unresolved = $Unresolved }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
        $controllers = $Controller
        Mock Get-MtAnssiAdDomainController -ModuleName Maester `
            -MockWith ({ $controllers }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdPrivilegedMemberCount' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'judges <Count> accounts in a <Domains>-domain forest as <Expected>' -ForEach @(
            @{ Count = 50; Domains = 1; Expected = $true }
            @{ Count = 51; Domains = 1; Expected = $false }
            @{ Count = 60; Domains = 20; Expected = $true }
            @{ Count = 61; Domains = 20; Expected = $false }
        ) {
            Use-Ad -Account @(Get-Population -Count $Count) -DomainCount $Domains

            Test-MtAnssiAdPrivilegedMemberCount | Should -Be $Expected
        }

        It 'does not count the RID 500 account and the domain controller accounts' {
            $computer = [PSCustomObject]@{ DistinguishedName = 'CN=DC1,DC=contoso,DC=com' }
            $controller = [PSCustomObject]@{ Type = 'Writable'; Computer = $computer }
            Use-Ad -Account (@(Get-Population -Count 50) + @(
                    Get-Account -Name 'Administrator' -Rid '500'
                    Get-Account -Name 'DC1' -Kind 'Computer' -Rid '1000'
                )) -Controller @($controller)

            Test-MtAnssiAdPrivilegedMemberCount | Should -Be $true

            Should -Invoke @detail -ParameterFilter { $Result -match 'has 50 privileged account' }
        }
    }

    Context 'data read' {
        It 'lists the privileged accounts and the domain controllers from the collected data' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedMemberCount

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'U1' -and
                @($Computer)[0].Name -eq 'C1' -and @($Group)[0].Name -eq 'G1' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdDomainController -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Computer)[0].Name -eq 'C1' -and @($DomainController)[0].Name -eq 'D1'
            }
        }

        It 'reads the Domain, Users, Computers, Groups and DomainControllers categories' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedMemberCount

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 5 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups' -and $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'result text' {
        It 'gives the count, the limit and the number of domains' {
            Use-Ad -Account @(Get-Population -Count 3) -DomainCount 20

            $null = Test-MtAnssiAdPrivilegedMemberCount

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^The domain has 3 privileged account\(s\)\. The limit is 60 ' -and
                $Result -match 'of the 20-domain forest'
            }
        }

        It 'lists the accounts by name with their type, state and groups when over the limit' {
            Use-Ad -Account (@(Get-Population -Count 49) + @(
                    Get-Account -Name 'zzz' -Kind 'Computer' -Rid '4001' `
                        -Group 'Administrators', 'Domain Admins'
                    Get-Account -Name 'aaa' -Rid '4002'
                ))

            $null = Test-MtAnssiAdPrivilegedMemberCount

            Should -Invoke @detail -ParameterFilter {
                $Result -match '\| contoso\.com \| aaa \|' -and
                $Result -match ('(?s)aaa \| User \| True \| Domain Admins \|.*' +
                    'zzz \| Computer \| True \| Administrators, Domain Admins \|')
            }
        }

        It 'says how many members were not checked, on a pass and on a failure' -ForEach @(
            @{ Count = 1 }
            @{ Count = 51 }
        ) {
            $unresolved = @([PSCustomObject]@{ DistinguishedName = 'CN=x'; Group = @('G') })
            Use-Ad -Account @(Get-Population -Count $Count) -Unresolved $unresolved

            $null = Test-MtAnssiAdPrivilegedMemberCount

            Should -Invoke @detail -ParameterFilter { $Result -match 'also hold 1 member\(s\)' }
        }

        It 'escapes markdown in an account name' {
            Use-Ad -Account (@(Get-Population -Count 50) + @(
                    Get-Account -Name '[click](https://evil.example)|x' -Rid '4003'))

            $null = Test-MtAnssiAdPrivilegedMemberCount

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped without reading when the <Missing> is missing' -ForEach @(
            @{ Missing = 'domain SID'; Sid = $null; Count = 1 }
            @{ Missing = 'domain count'; Sid = 'S-1-5-21-1-2-3'; Count = $null }
        ) {
            Use-Ad -DomainSid $Sid -DomainCount $Count

            Test-MtAnssiAdPrivilegedMemberCount | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'number of domains'
            }
        }

        It 'lets the exception reach the engine when the privileged accounts cannot be listed' {
            Use-Ad
            Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
                -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdPrivilegedMemberCount } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdPrivilegedMemberCount } | Should -Throw 'LDAP bind failed'

        }
    }
}
