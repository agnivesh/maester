BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-035.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdTrustDomainNotFiltered' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdTrustDomainNotFiltered {
        InModuleScope Maester { Test-MtAnssiAdTrustDomainNotFiltered }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-TrustFixture {
        param(
            [string] $Partner,
            [int] $Direction = 2,
            [int] $Type = 2,
            [int] $Attributes = 0
        )
        [PSCustomObject]@{
            TrustPartner    = $Partner
            TrustDirection  = $Direction
            TrustType       = $Type
            TrustAttributes = $Attributes
        }
    }
}

Describe 'Test-MtAnssiAdTrustDomainNotFiltered' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    # Direction: 0 disabled, 1 inbound, 2 outbound, 3 bidirectional.
    # Type: 1 downlevel, 2 uplevel, 3 MIT, 4 DCE.
    # Attributes: 0x4 QUARANTINED_DOMAIN, 0x8 FOREST_TRANSITIVE, 0x20 WITHIN_FOREST,
    # 0x40 TREAT_AS_EXTERNAL, 0x80 USES_RC4_ENCRYPTION (MIT only).
    Context 'verdict for a single trust relationship' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails for an outbound external trust without quarantine'
                Direction = 2; Type = 2; Attributes = 0x0; Expected = $false }
            @{ Name = 'fails for a bidirectional external trust without quarantine'
                Direction = 3; Type = 2; Attributes = 0x0; Expected = $false }
            @{ Name = 'fails for an outbound downlevel (NT4) trust without quarantine'
                Direction = 2; Type = 1; Attributes = 0x0; Expected = $false }
            @{ Name = 'fails when only unrelated flags are set'
                Direction = 2; Type = 2; Attributes = 0x12; Expected = $false }
            @{ Name = 'passes for a quarantined outbound trust'
                Direction = 2; Type = 2; Attributes = 0x4; Expected = $true }
            @{ Name = 'passes for a quarantined bidirectional trust with other flags'
                Direction = 3; Type = 2; Attributes = 0x14; Expected = $true }
            @{ Name = 'passes for a trust within the forest'
                Direction = 2; Type = 2; Attributes = 0x20; Expected = $true }
            @{ Name = 'passes for a forest trust'
                Direction = 2; Type = 2; Attributes = 0x8; Expected = $true }
            @{ Name = 'passes for a forest trust treated as external (not evaluated here)'
                Direction = 2; Type = 2; Attributes = 0x48; Expected = $true }
            @{ Name = 'passes for an inbound-only trust'
                Direction = 1; Type = 2; Attributes = 0x0; Expected = $true }
            @{ Name = 'passes for a disabled trust'
                Direction = 0; Type = 2; Attributes = 0x0; Expected = $true }
            @{ Name = 'passes for an MIT realm trust'
                Direction = 2; Type = 3; Attributes = 0x80; Expected = $true }
            @{ Name = 'passes for a DCE realm trust'
                Direction = 2; Type = 4; Attributes = 0x0; Expected = $true }
        ) {
            $state = [PSCustomObject]@{
                Trusts = @(Get-TrustFixture -Partner 'partner.example' -Direction $Direction `
                        -Type $Type -Attributes $Attributes)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustDomainNotFiltered | Should -Be $Expected
        }

        It 'reads only the Trusts category of the AD state' {
            $state = [PSCustomObject]@{ Trusts = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdTrustDomainNotFiltered

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Trusts' }
        }
    }

    Context 'several trust relationships' {
        BeforeEach {
            $state = [PSCustomObject]@{
                Trusts = @(
                    Get-TrustFixture -Partner 'bad.example'
                    Get-TrustFixture -Partner 'good.example' -Attributes 0x4
                    Get-TrustFixture -Partner 'worse.example' -Direction 3 -Type 1
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        }

        It 'fails when at least one trust is unfiltered' {
            Test-MtAnssiAdTrustDomainNotFiltered | Should -Be $false
        }

        It 'lists only the unfiltered trusts with their direction and type' {
            $null = Test-MtAnssiAdTrustDomainNotFiltered

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'bad\.example \| Outbound \| Uplevel' -and
                $Result -match 'worse\.example \| Bidirectional \| Downlevel' -and
                $Result -match 'Found 2 outbound' -and
                $Result -notmatch 'good\.example'
            }
        }

        It 'shows the trust attributes in hexadecimal' {
            $null = Test-MtAnssiAdTrustDomainNotFiltered

            Should -Invoke @detail -ParameterFilter { $Result -match '\| 0x0 \|' }
        }
    }

    Context 'no trust relationship' {
        It 'passes and says so when the trust list is empty' {
            $state = [PSCustomObject]@{ Trusts = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustDomainNotFiltered | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'No trust relationship is configured'
            }
        }

        It 'says no unfiltered trust was found when all trusts are filtered' {
            $state = [PSCustomObject]@{
                Trusts = @(Get-TrustFixture -Partner 'good.example' -Attributes 0x4)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustDomainNotFiltered | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'No unfiltered outbound domain trust relationship was found'
            }
        }
    }

    Context 'test cannot run' {
        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdTrustDomainNotFiltered } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'trust names come from the directory' {
        It 'escapes markdown in the trust partner name' {
            $state = [PSCustomObject]@{
                Trusts = @(Get-TrustFixture -Partner '[click](https://evil.example)|x')
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdTrustDomainNotFiltered

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    It 'is skipped when the <Collection> collection was not returned' -ForEach @(
        @{ Collection = 'Trusts' }
    ) {
        $props = [ordered]@{ Trusts = @() }
        $props[$Collection] = $null
        $state = [PSCustomObject]$props
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

        Test-MtAnssiAdTrustDomainNotFiltered | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
