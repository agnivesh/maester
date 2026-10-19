BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-072.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdTrustTgtDelegation' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdTrustTgtDelegation {
        InModuleScope Maester { Test-MtAnssiAdTrustTgtDelegation }
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
            [int] $Direction = 1,
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

Describe 'Test-MtAnssiAdTrustTgtDelegation' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    # Direction: 0 disabled, 1 inbound, 2 outbound, 3 bidirectional.
    # Attributes: 0x8 FOREST_TRANSITIVE, 0x10 CROSS_ORGANIZATION, 0x200 NO_TGT_DELEGATION,
    # 0x800 ENABLE_TGT_DELEGATION.
    Context 'verdict for a single trust relationship' {
        It '<Name>' -ForEach @(
            @{ Name = 'fails for an inbound trust that allows TGT delegation'
                Direction = 1; Attributes = 0x800; Expected = $false }
            @{ Name = 'fails for a bidirectional trust that allows TGT delegation'
                Direction = 3; Attributes = 0x800; Expected = $false }
            @{ Name = 'fails for a cross-organization forest trust that allows it'
                Direction = 1; Attributes = 0x818; Expected = $false }
            @{ Name = 'fails when the enable flag wins over the no-delegation flag'
                Direction = 1; Attributes = 0xA00; Expected = $false }
            @{ Name = 'passes for an inbound trust without the flag'
                Direction = 1; Attributes = 0x0; Expected = $true }
            @{ Name = 'passes for an inbound trust that denies TGT delegation'
                Direction = 1; Attributes = 0x210; Expected = $true }
            @{ Name = 'passes for an inbound forest trust with unrelated flags'
                Direction = 1; Attributes = 0x18; Expected = $true }
            @{ Name = 'passes for an outbound-only trust that has the flag'
                Direction = 2; Attributes = 0x800; Expected = $true }
            @{ Name = 'passes for a disabled trust that has the flag'
                Direction = 0; Attributes = 0x800; Expected = $true }
        ) {
            $state = [PSCustomObject]@{
                Trusts = @(Get-TrustFixture -Partner 'partner.example' -Direction $Direction `
                        -Attributes $Attributes)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustTgtDelegation | Should -Be $Expected
        }

        It 'reads only the Trusts category of the AD state' {
            $state = [PSCustomObject]@{ Trusts = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdTrustTgtDelegation

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Trusts' }
        }
    }

    Context 'several trust relationships' {
        BeforeEach {
            $state = [PSCustomObject]@{
                Trusts = @(
                    Get-TrustFixture -Partner 'bad.example' -Attributes 0x800
                    Get-TrustFixture -Partner 'good.example' -Attributes 0x200
                    Get-TrustFixture -Partner 'worse.example' -Direction 3 -Attributes 0x808
                    Get-TrustFixture -Partner 'outbound.example' -Direction 2 -Attributes 0x800
                )
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        }

        It 'fails when at least one inbound trust allows delegation' {
            Test-MtAnssiAdTrustTgtDelegation | Should -Be $false
        }

        It 'lists only the delegating trusts with their direction and attributes' {
            $null = Test-MtAnssiAdTrustTgtDelegation

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'bad\.example \| Inbound \| 0x800' -and
                $Result -match 'worse\.example \| Bidirectional \| 0x808' -and
                $Result -match 'Found 2 inbound' -and
                $Result -notmatch 'good\.example' -and
                $Result -notmatch 'outbound\.example'
            }
        }
    }

    Context 'no trust relationship' {
        It 'passes and says so when the trust list is empty' {
            $state = [PSCustomObject]@{ Trusts = @() }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustTgtDelegation | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'No trust relationship is configured'
            }
        }

        It 'says none was found when no inbound trust allows delegation' {
            $state = [PSCustomObject]@{
                Trusts = @(Get-TrustFixture -Partner 'good.example' -Attributes 0x200)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdTrustTgtDelegation | Should -BeTrue

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'No inbound trust relationship allowing Kerberos delegation'
            }
        }
    }

    Context 'test cannot run' {
        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdTrustTgtDelegation } | Should -Throw 'LDAP bind failed'

        }
    }

    Context 'trust names come from the directory' {
        It 'escapes markdown in the trust partner name' {
            $partner = '[click](https://evil.example)|x'
            $state = [PSCustomObject]@{
                Trusts = @(Get-TrustFixture -Partner $partner -Attributes 0x800)
            }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            $null = Test-MtAnssiAdTrustTgtDelegation

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

        Test-MtAnssiAdTrustTgtDelegation | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
