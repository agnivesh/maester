BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-070.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPrivilegedSecurityDescriptorReadable' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPrivilegedSecurityDescriptorReadable {
        InModuleScope Maester { Test-MtAnssiAdPrivilegedSecurityDescriptorReadable }
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
            [AllowNull()] [object] $Enabled = $true,
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
                Enabled        = $Enabled
                LastLogonDate  = [datetime]'2025-06-01'
            }
        }
    }

    function Use-Ad {
        param(
            [object[]] $Account = @(),
            [string[]] $UnreadableName = @(),
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
        $unreadable = @($Account | Where-Object { $_.Item.Name -in $UnreadableName })
        Mock Get-MtAnssiAdUnreadableDescriptor -ModuleName Maester `
            -MockWith ({ $unreadable }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdPrivilegedSecurityDescriptorReadable' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when every privileged account descriptor can be read' {
            Use-Ad -Account @(Get-Account -Name 'alice'; Get-Account -Name 'DC1' -Kind 'Computer')

            Test-MtAnssiAdPrivilegedSecurityDescriptorReadable | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match ('The security descriptor of all 2 privileged accounts ' +
                    'could be read\.')
            }
        }

        It 'fails when the descriptor of a privileged account cannot be read' -ForEach @(
            @{ Kind = 'User'; Enabled = $true }
            @{ Kind = 'Computer'; Enabled = $true }
            @{ Kind = 'User'; Enabled = $false }
        ) {
            Use-Ad -Account @(
                Get-Account -Name 'alice' -Kind $Kind -Enabled $Enabled
                Get-Account -Name 'bob'
            ) -UnreadableName 'alice'

            Test-MtAnssiAdPrivilegedSecurityDescriptorReadable | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match `
                    '^The security descriptor of 1 of 2 privileged accounts could not' -and
                $Result -match '\| contoso\.com \|'
            }
        }
    }

    Context 'data read' {
        It 'lists the privileged accounts and reads the descriptors of all of them' {
            Use-Ad -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob')

            $null = Test-MtAnssiAdPrivilegedSecurityDescriptorReadable

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $DomainSid -eq 'S-1-5-21-1-2-3' -and @($User)[0].Name -eq 'U1' -and
                @($Computer)[0].Name -eq 'C1' -and @($Group)[0].Name -eq 'G1' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
            Should -Invoke Get-MtAnssiAdUnreadableDescriptor -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Account).Count -eq 2 -and $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }

        It 'reads the Domain, Users, Computers and Groups categories' {
            Use-Ad

            $null = Test-MtAnssiAdPrivilegedSecurityDescriptorReadable

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
        }
    }

    Context 'result text' {
        It 'lists the accounts by name with their type and the groups they reach' {
            Use-Ad -Account @(
                Get-Account -Name 'zed' -Kind 'Computer' -Group 'Administrators', 'Domain Admins'
                Get-Account -Name 'amy'
            ) -UnreadableName 'zed', 'amy'

            $null = Test-MtAnssiAdPrivilegedSecurityDescriptorReadable

            Should -Invoke @detail -ParameterFilter {
                $Result -match ('(?s)amy \| User \| Domain Admins \|.*' +
                    'zed \| Computer \| Administrators, Domain Admins \|')
            }
        }

        It 'says how many members were not checked, on a pass and on a failure' -ForEach @(
            @{ Unreadable = @() }
            @{ Unreadable = @('alice') }
        ) {
            $unresolved = @([PSCustomObject]@{ DistinguishedName = 'CN=x'; Group = @('G') })
            Use-Ad -Account @(Get-Account -Name 'alice') -UnreadableName $Unreadable `
                -Unresolved $unresolved

            $null = Test-MtAnssiAdPrivilegedSecurityDescriptorReadable

            Should -Invoke @detail -ParameterFilter { $Result -match 'also hold 1 member\(s\)' }
        }

        It 'escapes markdown in an account name' {
            $name = '[click](https://evil.example)|x'
            Use-Ad -Account @(Get-Account -Name $name) -UnreadableName $name

            $null = Test-MtAnssiAdPrivilegedSecurityDescriptorReadable

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped without reading when the domain SID is missing' {
            Use-Ad -DomainSid $null

            Test-MtAnssiAdPrivilegedSecurityDescriptorReadable | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdPrivilegedAccount -ModuleName Maester -Times 0 -Exactly
            Should -Invoke Get-MtAnssiAdUnreadableDescriptor -ModuleName Maester -Times 0 -Exactly
            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'lets the exception reach the engine when <Helper> fails' -ForEach @(
            @{ Helper = 'Get-MtAnssiAdPrivilegedAccount' }
            @{ Helper = 'Get-MtAnssiAdUnreadableDescriptor' }
        ) {
            Use-Ad
            Mock $Helper -ModuleName Maester -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdPrivilegedSecurityDescriptorReadable } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdPrivilegedSecurityDescriptorReadable } | Should -Throw 'LDAP bind failed'

        }
    }
}
