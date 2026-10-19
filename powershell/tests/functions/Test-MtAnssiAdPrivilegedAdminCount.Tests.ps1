BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-051.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrivilegedAdminCount' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrivilegedAdminCount {
        InModuleScope Maester { Test-MtAnssiAdPrivilegedAdminCount }
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
            [hashtable] $Property = @{},
            [string[]] $Group = @('Domain Admins'),
            [string[]] $Link = @('Member')
        )
        $item = [ordered]@{
            Name                  = $Name
            SamAccountName        = $Name
            Enabled               = $true
            PasswordNeverExpires  = $false
            DoesNotRequirePreAuth = $false
            UserAccountControl    = 0x200
            AdminCount            = 1
            ServicePrincipalName  = [string[]]@()
            PasswordLastSet       = [datetime]'2025-01-01'
            LastLogonDate         = [datetime]'2025-06-01'
        }
        foreach ($key in $Property.Keys) { $item[$key] = $Property[$key] }
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Kind              = $Kind
            Group             = $Group
            Link              = $Link
            Item              = [PSCustomObject]$item
        }
    }

    function Use-Ad {
        param(
            [object[]] $Account = @(),
            [object[]] $Unresolved = @(),
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3'
        )
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{ DomainSID = $domainSidValue }
            Users            = @([PSCustomObject]@{ Name = 'U1' })
            Computers        = @([PSCustomObject]@{ Name = 'C1' })
            Groups           = @([PSCustomObject]@{ Name = 'G1' })
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $privileged = [PSCustomObject]@{ Account = $Account; Unresolved = $Unresolved }
        Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
            -MockWith ({ $privileged }.GetNewClosure())
    }

    $script:bad = @{ AdminCount = 0 }
}

Describe 'Test-MtAnssiAdPrivilegedAdminCount' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when no privileged user account is affected' {
            Use-Ad -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob')

            Test-MtAnssiAdPrivilegedAdminCount | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'All 2 privileged user accounts that are members'
            }
        }

        It 'fails when a privileged user account is affected' {
            Use-Ad -Account @(
                Get-Account -Name 'alice' -Property $bad
                Get-Account -Name 'bob'
            )

            Test-MtAnssiAdPrivilegedAdminCount | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match `
                    '^1 of 2 privileged user accounts that are members of a protected' -and
                $Result -match '\| contoso\.com \|'
            }
        }

        It 'ignores a privileged computer account' {
            Use-Ad -Account @(Get-Account -Name 'DC1' -Kind 'Computer' -Property $bad)

            Test-MtAnssiAdPrivilegedAdminCount | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'All 0 privileged'
            }
        }

        It 'checks a disabled privileged user as well' {
            Use-Ad -Account @(Get-Account -Name 'alice' -Property ($bad + @{ Enabled = $false }))

            Test-MtAnssiAdPrivilegedAdminCount | Should -Be $false
        }

        It 'judges adminCount <Case>' -ForEach @(
            @{ Case = 'not set as a failure'; Value = $null; Expected = $false }
            @{ Case = '0 as a failure'; Value = 0; Expected = $false }
            @{ Case = 'text 0 as a failure'; Value = '0'; Expected = $false }
            @{ Case = '1 as a pass'; Value = 1; Expected = $true }
            @{ Case = 'text 1 as a pass'; Value = '1'; Expected = $true }
        ) {
            Use-Ad -Account @(Get-Account -Name 'alice' -Property @{ AdminCount = $Value })

            Test-MtAnssiAdPrivilegedAdminCount | Should -Be $Expected
        }

        It 'does not check an account that is privileged only through its primary group' {
            $account = Get-Account -Name 'alice' -Property @{ AdminCount = $null } `
                -Link 'PrimaryGroup'
            Use-Ad -Account @($account)

            Test-MtAnssiAdPrivilegedAdminCount | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'All 0 privileged'
            }
        }

        It 'checks an account that is privileged through <Case>' -ForEach @(
            @{ Case = 'a protected account'; Link = @('ProtectedAccount') }
            @{ Case = 'its primary group and a membership'; Link = @('Member', 'PrimaryGroup') }
        ) {
            $account = Get-Account -Name 'alice' -Property @{ AdminCount = $null } -Link $Link
            Use-Ad -Account @($account)

            Test-MtAnssiAdPrivilegedAdminCount | Should -Be $false
        }
    }

    Context 'privileged accounts' {
        It 'lists the privileged accounts from the collected data' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedAdminCount

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'U1' -and
                @($Computer)[0].Name -eq 'C1' -and @($Group)[0].Name -eq 'G1' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }
    }

    Context 'result text' {

        It 'lists the accounts by name with their adminCount and the groups they reach' {
            $newer = @{ AdminCount = 0; PasswordLastSet = [datetime]'2023-05-01' }
            $older = @{ AdminCount = $null; PasswordLastSet = [datetime]'2021-02-03' }
            Use-Ad -Account @(
                Get-Account -Name 'amy' -Property $newer
                Get-Account -Name 'zed' -Property $older -Group 'Administrators', 'Domain Admins'
            )

            $null = Test-MtAnssiAdPrivilegedAdminCount

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match ('(?s)amy \| 0 \| True \| Domain Admins \|.*' +
                    'zed \| not set \| True \| Administrators, Domain Admins \|')
            }
        }
        It 'says how many members were not checked, on a pass and on a failure' -ForEach @(
            @{ Affected = $false }
            @{ Affected = $true }
        ) {
            $unresolved = @([PSCustomObject]@{ DistinguishedName = 'CN=x'; Group = @('G') })
            $property = @{}
            if ($Affected) { $property = $bad }
            Use-Ad -Account @(Get-Account -Name 'alice' -Property $property) `
                -Unresolved $unresolved

            $null = Test-MtAnssiAdPrivilegedAdminCount

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'also hold 1 member\(s\)'
            }
        }

        It 'escapes markdown in an account name' {
            $name = '[click](https://evil.example)|x'
            Use-Ad -Account @(Get-Account -Name $name -Property $bad)

            $null = Test-MtAnssiAdPrivilegedAdminCount

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Domain, Users, Computers and Groups categories' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedAdminCount

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped without listing accounts when the domain SID is missing' {
            Use-Ad -DomainSid $null

            Test-MtAnssiAdPrivilegedAdminCount | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'lets the exception reach the engine when the privileged accounts cannot be listed' {
            Use-Ad
            Mock Get-MtAnssiAdPrivilegedAccount -ModuleName Maester `
                -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdPrivilegedAdminCount } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdPrivilegedAdminCount } | Should -Throw 'LDAP bind failed'

        }
    }
}
