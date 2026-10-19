BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:base = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=x'
    $script:services = "CN=Enrollment Services,$script:base"
    $script:ntAuthDn = "CN=NTAuthCertificates,$script:base"

    function Get-ServiceFixture {
        param([string] $Name, [AllowNull()] $Template)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,$script:services"
            Name              = $Name
            ObjectClass       = @('top', 'pKIEnrollmentService')
            Attribute         = [ordered]@{ certificateTemplates = $Template }
        }
    }

    function Get-CertificateFixture {
        param([string] $Dn, [string] $Name, [object[]] $Bytes)
        [PSCustomObject]@{ DistinguishedName = $Dn; Name = $Name; Certificate = $Bytes }
    }

    function Get-NtAuthFixture {
        param([object[]] $Bytes)
        Get-CertificateFixture -Dn $script:ntAuthDn -Name 'NTAuthCertificates' -Bytes $Bytes
    }

    function Get-CaFixture {
        param([string] $Name, [object[]] $Bytes)
        Get-CertificateFixture -Dn "CN=$Name,$script:services" -Name $Name -Bytes $Bytes
    }

    function Get-Publication {
        param([object[]] $Service, [object[]] $Certificate)
        InModuleScope Maester -Parameters @{ Service = $Service; Certificate = $Certificate } {
            param($Service, $Certificate)
            Get-MtAnssiAdTemplatePublication -EnrollmentService $Service `
                -CaCertificate $Certificate
        }
    }
}

Describe 'Get-MtAnssiAdTemplatePublication' {
    It 'lists the templates of a CA that is in the NTAuth store as published and trusted' {
        $service = Get-ServiceFixture -Name 'CA1' -Template @('A', 'B')
        $certificate = @(
            Get-NtAuthFixture -Bytes @(,[byte[]](1, 2, 3))
            Get-CaFixture -Name 'CA1' -Bytes @(,[byte[]](1, 2, 3))
        )

        $result = Get-Publication -Service @($service) -Certificate $certificate

        @($result.Published | Sort-Object) | Should -Be @('A', 'B')
        @($result.Trusted | Sort-Object) | Should -Be @('A', 'B')
    }

    It 'lists the templates of a CA that is not in the NTAuth store as published only' {
        $service = Get-ServiceFixture -Name 'CA1' -Template @('A')
        $certificate = @(
            Get-NtAuthFixture -Bytes @(,[byte[]](9, 9))
            Get-CaFixture -Name 'CA1' -Bytes @(,[byte[]](1, 2, 3))
        )

        $result = Get-Publication -Service @($service) -Certificate $certificate

        @($result.Published) | Should -Be @('A')
        @($result.Trusted).Count | Should -Be 0
    }

    It 'compares the whole certificate, not its start' {
        $service = Get-ServiceFixture -Name 'CA1' -Template @('A')
        $certificate = @(
            Get-NtAuthFixture -Bytes @(,[byte[]](1, 2, 3, 4))
            Get-CaFixture -Name 'CA1' -Bytes @(,[byte[]](1, 2, 3))
        )

        @((Get-Publication -Service @($service) -Certificate $certificate).Trusted).Count |
            Should -Be 0
    }

    It 'trusts a template when one of the CAs that publish it is in the NTAuth store' {
        $services = @(
            Get-ServiceFixture -Name 'Untrusted' -Template @('A', 'B')
            Get-ServiceFixture -Name 'Trusted' -Template @('B')
        )
        $certificate = @(
            Get-NtAuthFixture -Bytes @(,[byte[]](2))
            Get-CaFixture -Name 'Untrusted' -Bytes @(,[byte[]](1))
            Get-CaFixture -Name 'Trusted' -Bytes @(,[byte[]](2))
        )

        $result = Get-Publication -Service $services -Certificate $certificate

        @($result.Published | Sort-Object) | Should -Be @('A', 'B')
        @($result.Trusted) | Should -Be @('B')
    }

    It 'finds the certificate of a CA with any of several values in the store' {
        $service = Get-ServiceFixture -Name 'CA1' -Template @('A')
        $certificate = @(
            Get-NtAuthFixture -Bytes @([byte[]](7), [byte[]](1, 2), [byte[]](8))
            Get-CaFixture -Name 'CA1' -Bytes @([byte[]](5), [byte[]](1, 2))
        )

        @((Get-Publication -Service @($service) -Certificate $certificate).Trusted) |
            Should -Be @('A')
    }

    It 'ignores case in template names and distinguished names' {
        $service = Get-ServiceFixture -Name 'CA1' -Template @('Web')
        $certificate = @(
            Get-NtAuthFixture -Bytes @(,[byte[]](1))
            Get-CertificateFixture -Dn "cn=ca1,$($script:services.ToLower())" -Name 'CA1' `
                -Bytes @(,[byte[]](1))
        )

        $result = Get-Publication -Service @($service) -Certificate $certificate

        $result.Published.Contains('WEB') | Should -Be $true
        $result.Trusted.Contains('web') | Should -Be $true
    }

    It 'does not trust a CA that has no certificate in the directory' {
        $service = Get-ServiceFixture -Name 'CA1' -Template @('A')
        $certificate = @(Get-NtAuthFixture -Bytes @(,[byte[]](1)))

        $result = Get-Publication -Service @($service) -Certificate $certificate

        @($result.Published) | Should -Be @('A')
        @($result.Trusted).Count | Should -Be 0
    }

    It 'trusts nothing when the NTAuth store is empty' {
        $service = Get-ServiceFixture -Name 'CA1' -Template @('A')
        $certificate = @(
            Get-NtAuthFixture -Bytes @()
            Get-CaFixture -Name 'CA1' -Bytes @(,[byte[]](1))
        )

        @((Get-Publication -Service @($service) -Certificate $certificate).Trusted).Count |
            Should -Be 0
    }

    It 'accepts one template given as text and a CA without templates' -ForEach @(
        @{ Template = 'A'; Expected = @('A') }
        @{ Template = $null; Expected = @() }
    ) {
        $service = Get-ServiceFixture -Name 'CA1' -Template $Template
        $certificate = @(
            Get-NtAuthFixture -Bytes @(,[byte[]](1))
            Get-CaFixture -Name 'CA1' -Bytes @(,[byte[]](1))
        )

        $result = Get-Publication -Service @($service) -Certificate $certificate

        @($result.Published).Count | Should -Be $Expected.Count
        @($result.Trusted).Count | Should -Be $Expected.Count
    }

    It 'publishes but trusts nothing when the NTAuth store is not among the certificates' {
        $service = Get-ServiceFixture -Name 'CA1' -Template @('A')
        $certificate = @(Get-CaFixture -Name 'CA1' -Bytes @(, [byte[]](1)))

        $result = Get-Publication -Service @($service) -Certificate $certificate

        @($result.Published) | Should -Be @('A')
        @($result.Trusted).Count | Should -Be 0
    }

    It 'returns empty sets for no CAs' {
        $certificate = @(Get-NtAuthFixture -Bytes @(,[byte[]](1)))

        $result = Get-Publication -Service @() -Certificate $certificate

        @($result.Published).Count | Should -Be 0
        @($result.Trusted).Count | Should -Be 0
    }
}
