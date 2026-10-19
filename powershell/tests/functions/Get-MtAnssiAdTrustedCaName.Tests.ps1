BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:base = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=x'

    function Get-StoreFixture {
        param([object[]] $Bytes)
        [PSCustomObject]@{
            DistinguishedName = "CN=NTAuthCertificates,$script:base"
            Name              = 'NTAuthCertificates'
            Certificate       = $Bytes
        }
    }

    function Get-CaFixture {
        param([string] $Name, [object[]] $Bytes, [string] $Container = 'Enrollment Services')
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=$Container,$script:base"
            Name              = $Name
            Certificate       = $Bytes
        }
    }

    function Get-Trusted {
        param([object[]] $Certificate)
        InModuleScope Maester -Parameters @{ Certificate = $Certificate } {
            param($Certificate)
            $set = Get-MtAnssiAdTrustedCaName -CaCertificate $Certificate
            [PSCustomObject]@{ Set = $set }
        }
    }
}

Describe 'Get-MtAnssiAdTrustedCaName' {
    It 'returns the CAs whose certificate is in the store and not the others' {
        $result = Get-Trusted -Certificate @(
            Get-StoreFixture -Bytes @(, [byte[]](1, 2, 3))
            Get-CaFixture -Name 'In' -Bytes @(, [byte[]](1, 2, 3))
            Get-CaFixture -Name 'Out' -Bytes @(, [byte[]](4, 5, 6))
        )

        $result.Set -is [System.Collections.Generic.HashSet[string]] | Should -Be $true
        @($result.Set) | Should -Be @("CN=In,CN=Enrollment Services,$script:base")
    }

    It 'compares the whole certificate, not its start or its length' -ForEach @(
        @{ Name = 'longer'; Bytes = @(1, 2, 3, 4) }
        @{ Name = 'shorter'; Bytes = @(1, 2) }
        @{ Name = 'different last byte'; Bytes = @(1, 2, 4) }
    ) {
        $result = Get-Trusted -Certificate @(
            Get-StoreFixture -Bytes @(, [byte[]](1, 2, 3))
            Get-CaFixture -Name 'CA' -Bytes @(, [byte[]]$Bytes)
        )

        $result.Set.Count | Should -Be 0
    }

    It 'trusts a CA when any of its certificates is in the store' {
        $result = Get-Trusted -Certificate @(
            Get-StoreFixture -Bytes @([byte[]](7), [byte[]](1, 2), [byte[]](8))
            Get-CaFixture -Name 'CA' -Bytes @([byte[]](5), [byte[]](1, 2))
        )

        $result.Set.Count | Should -Be 1
    }

    It 'does not repeat a CA that has several certificates in the store' {
        $result = Get-Trusted -Certificate @(
            Get-StoreFixture -Bytes @([byte[]](1), [byte[]](2))
            Get-CaFixture -Name 'CA' -Bytes @([byte[]](1), [byte[]](2))
        )

        $result.Set.Count | Should -Be 1
    }

    It 'ignores case in the distinguished name' {
        $result = Get-Trusted -Certificate @(
            Get-StoreFixture -Bytes @(, [byte[]](1))
            Get-CaFixture -Name 'CA' -Bytes @(, [byte[]](1))
        )

        $result.Set.Contains("cn=ca,cn=enrollment services,$($script:base.ToUpper())") |
            Should -Be $true
    }

    It 'includes any other object that holds a certificate of the store' {
        $result = Get-Trusted -Certificate @(
            Get-StoreFixture -Bytes @(, [byte[]](1))
            Get-CaFixture -Name 'Root' -Bytes @(, [byte[]](1)) -Container 'AIA'
        )

        @($result.Set) | Should -Be @("CN=Root,CN=AIA,$script:base")
    }

    It 'does not return the store itself' {
        $result = Get-Trusted -Certificate @(Get-StoreFixture -Bytes @(, [byte[]](1)))

        $result.Set.Count | Should -Be 0
    }

    It 'does not trust a CA without certificates' -ForEach @(
        @{ Bytes = @() }
        @{ Bytes = $null }
    ) {
        $result = Get-Trusted -Certificate @(
            Get-StoreFixture -Bytes @(, [byte[]](1))
            Get-CaFixture -Name 'CA' -Bytes $Bytes
        )

        $result.Set.Count | Should -Be 0
    }

    It 'trusts nothing when the store is empty' {
        $result = Get-Trusted -Certificate @(
            Get-StoreFixture -Bytes @()
            Get-CaFixture -Name 'CA' -Bytes @(, [byte[]](1))
        )

        $result.Set.Count | Should -Be 0
    }

    It 'trusts no CA when the store is not among the certificates' {
        $certificate = @(Get-CaFixture -Name 'CA' -Bytes @(, [byte[]](1)))

        (Get-Trusted -Certificate $certificate).Set.Count | Should -Be 0
    }

    It 'trusts no CA when there are no certificates at all' {
        (Get-Trusted -Certificate @()).Set.Count | Should -Be 0
    }
}
