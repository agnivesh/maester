BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-036.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdTrustForestSidHistory' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdTrustForestSidHistory {
        InModuleScope Maester { Test-MtAnssiAdTrustForestSidHistory }
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

Describe 'Test-MtAnssiAdTrustForestSidHistory' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    # Direction: 0 disabled, 1 inbound, 2 outbound, 3 bidirectional.
    # Attributes: 0x4 QUARANTINED_DOMAIN, 0x8 FOREST_TRANSITIVE, 0x10 CROSS_ORGANIZATION,
    # 0x20 WITHIN_FOREST, 0x40 TREAT_AS_EXTERNAL, 0x400 PIM_TRUST.
    Context 'verdict for a single trust relationship' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails for an outbound forest trust with SID history enabled'
                Direction = 2; Attributes = 0x48; Expected = $false }
            @{ Name = 'fails for a bidirectional forest trust with SID history enabled'
                Direction = 3; Attributes = 0x48; Expected = $false }
            @{ Name = 'fails when other flags are set as well'
                Direction = 2; Attributes = 0x58; Expected = $false }
            @{ Name = 'fails for a PIM trust, its filtering is relaxed too'
                Direction = 2; Attributes = 0x448; Expected = $false }
            @{ Name = 'passes for a forest trust with default filtering'
                Direction = 2; Attributes = 0x8; Expected = $true }
            @{ Name = 'passes for a forest trust with only unrelated flags'
                Direction = 2; Attributes = 0x18; Expected = $true }
            @{ Name = 'passes for an inbound-only forest trust with SID history enabled'
                Direction = 1; Attributes = 0x48; Expected = $true }
            @{ Name = 'passes for a disabled forest trust with SID history enabled'
                Direction = 0; Attributes = 0x48; Expected = $true }
            @{ Name = 'passes for an external trust, the flag only applies to forest trusts'
                Direction = 2; Attributes = 0x40; Expected = $true }
            @{ Name = 'passes for an external trust without quarantine (other test)'
                Direction = 2; Attributes = 0x0; Expected = $true }
            @{ Name = 'passes for a quarantined external trust'
                Direction = 2; Attributes = 0x4; Expected = $true }
            @{ Name = 'passes for a trust within the forest'
                Direction = 2; Attributes = 0x20; Expected = $true }
        ) {
            $state = [PSCustomObject]@{
                Trusts = @(Get-TrustFixture -Partner 'partner.example' -Direction $Direction `
                        -Attributes $Attributes)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustForestSidHistory | Should -Be $Expected
        }

        It 'reads only the Trusts category of the AD state' {
            $state = [PSCustomObject]@{ Trusts = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdTrustForestSidHistory

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Trusts' }
        }
    }

    Context 'several trust relationships' {
        BeforeEach {
            $state = [PSCustomObject]@{
                Trusts = @(
                    Get-TrustFixture -Partner 'bad.example' -Attributes 0x48
                    Get-TrustFixture -Partner 'good.example' -Attributes 0x8
                    Get-TrustFixture -Partner 'worse.example' -Direction 3 -Attributes 0x48
                    Get-TrustFixture -Partner 'external.example' -Attributes 0x0
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        }

        It 'fails when at least one forest trust has SID history enabled' {
            Test-MtAnssiAdTrustForestSidHistory | Should -Be $false
        }

        It 'lists only the relaxed forest trusts with their direction and attributes' {
            $null = Test-MtAnssiAdTrustForestSidHistory

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'bad\.example \| Outbound \| 0x48' -and
                $Result -match 'worse\.example \| Bidirectional \| 0x48' -and
                $Result -match 'Found 2 outbound' -and
                $Result -notmatch 'good\.example' -and
                $Result -notmatch 'external\.example'
            }
        }
    }

    Context 'no trust relationship' {
        It 'passes and says so when the trust list is empty' {
            $state = [PSCustomObject]@{ Trusts = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustForestSidHistory | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'No trust relationship is configured'
            }
        }

        It 'says none was found when no forest trust has SID history enabled' {
            $state = [PSCustomObject]@{
                Trusts = @(Get-TrustFixture -Partner 'good.example' -Attributes 0x8)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustForestSidHistory | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'No outbound forest trust relationship with SID history enabled'
            }
        }
    }

    Context 'test cannot run' {
        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdTrustForestSidHistory } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'trust names come from the directory' {
        It 'escapes markdown in the trust partner name' {
            $partner = '[click](https://evil.example)|x'
            $state = [PSCustomObject]@{
                Trusts = @(Get-TrustFixture -Partner $partner -Attributes 0x48)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdTrustForestSidHistory

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

        Test-MtAnssiAdTrustForestSidHistory | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
