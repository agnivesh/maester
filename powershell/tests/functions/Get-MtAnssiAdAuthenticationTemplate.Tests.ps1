BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:clientAuth = '1.3.6.1.5.5.7.3.2'
    $script:serverAuth = '1.3.6.1.5.5.7.3.1'

    function Get-TemplateFixture {
        param(
            [string] $Name = 'T',
            [AllowNull()] $NameFlag = 1,
            [AllowNull()] $Eku = @('1.3.6.1.5.5.7.3.2'),
            [AllowNull()] $EnrollmentFlag = 0,
            [AllowNull()] $RaSignature = 0
        )
        $attribute = [ordered]@{
            'msPKI-Certificate-Name-Flag' = $NameFlag
            'pKIExtendedKeyUsage'         = $Eku
            'msPKI-Enrollment-Flag'       = $EnrollmentFlag
            'msPKI-RA-Signature'          = $RaSignature
        }
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=Certificate Templates,CN=Public Key Services"
            Name              = $Name
            ObjectClass       = @('top', 'pKICertificateTemplate')
            Attribute         = $attribute
        }
    }

    function Get-Selected {
        param([object[]] $Template)
        InModuleScope Maester -Parameters @{ Template = $Template } {
            param($Template)
            @(Get-MtAnssiAdAuthenticationTemplate -Template $Template)
        }
    }
}

Describe 'Get-MtAnssiAdAuthenticationTemplate' {
    Context 'the requester names the certificate' {
        It 'keeps a template whose name flags are <Name>' -ForEach @(
            @{ Name = 'supply the subject'; Flag = 1 }
            @{ Name = 'supply the subject alternative name'; Flag = 0x10000 }
            @{ Name = 'supply both'; Flag = 0x10001 }
            @{ Name = 'supply the subject among others'; Flag = 0x42000001 }
            @{ Name = 'text holding the subject bit'; Flag = '1' }
            @{ Name = 'a value above 2 GB with the subject bit'; Flag = 2147483649 }
            @{ Name = 'a negative text value with the subject bit'; Flag = '-2147483647' }
            @{ Name = 'a negative text value with the alternative name bit'; Flag = '-2147418112' }
        ) {
            $result = Get-Selected -Template @(Get-TemplateFixture -Name 'X' -NameFlag $Flag)

            @($result.Name) | Should -Be @('X')
        }

        It 'drops a template whose name flags are <Name>' -ForEach @(
            @{ Name = 'built from the directory'; Flag = 0x42000000 }
            @{ Name = 'zero'; Flag = 0 }
            @{ Name = 'only the old certificate bit'; Flag = 8 }
            @{ Name = 'a value above 2 GB without the bits'; Flag = 2147483648 }
            @{ Name = 'a negative text value built from the directory'; Flag = '-1509949440' }
            @{ Name = 'a negative text value without the bits'; Flag = '-2147483648' }
            @{ Name = 'missing'; Flag = $null }
            @{ Name = 'not a number'; Flag = 'x' }
        ) {
            Get-Selected -Template @(Get-TemplateFixture -NameFlag $Flag) | Should -BeNullOrEmpty
        }
    }

    Context 'the certificate can be used to log on' {
        It 'keeps a template with the <Name> usage' -ForEach @(
            @{ Name = 'client authentication'; Eku = '1.3.6.1.5.5.7.3.2' }
            @{ Name = 'PKINIT client authentication'; Eku = '1.3.6.1.5.2.3.4' }
            @{ Name = 'smart card logon'; Eku = '1.3.6.1.4.1.311.20.2.2' }
            @{ Name = 'any purpose'; Eku = '2.5.29.37.0' }
        ) {
            $single = Get-Selected -Template @(Get-TemplateFixture -Name 'X' -Eku $Eku)
            $list = Get-Selected -Template @(
                Get-TemplateFixture -Name 'Y' -Eku @($script:serverAuth, $Eku))

            @($single.Name) | Should -Be @('X')
            @($list.Name) | Should -Be @('Y')
        }

        It 'keeps a template with no usage restriction' -ForEach @(
            @{ Name = 'missing'; Eku = $null }
            @{ Name = 'empty'; Eku = @() }
        ) {
            $result = Get-Selected -Template @(Get-TemplateFixture -Name 'X' -Eku $Eku)

            @($result.Name) | Should -Be @('X')
        }

        It 'drops a template that only has other usages' -ForEach @(
            @{ Eku = '1.3.6.1.5.5.7.3.1' }
            @{ Eku = @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.3') }
            @{ Eku = '1.3.6.1.4.1.311.10.3.4' }
        ) {
            Get-Selected -Template @(Get-TemplateFixture -Eku $Eku) | Should -BeNullOrEmpty
        }
    }

    Context 'approval' {
        It 'flags a template that <Name>' -ForEach @(
            @{ Name = 'holds all requests for a manager'; Enrollment = 2; Signature = 0 }
            @{ Name = 'holds requests among other flags'; Enrollment = 10; Signature = 0 }
            @{ Name = 'needs one authorized signature'; Enrollment = 0; Signature = 1 }
            @{ Name = 'needs several authorized signatures'; Enrollment = 0; Signature = '3' }
        ) {
            $template = Get-TemplateFixture -EnrollmentFlag $Enrollment -RaSignature $Signature

            (Get-Selected -Template @($template))[0].ApprovalRequired | Should -Be $true
        }

        It 'does not flag a template that <Name>' -ForEach @(
            @{ Name = 'has plain flags'; Enrollment = 0; Signature = 0 }
            @{ Name = 'has other enrollment flags'; Enrollment = 8; Signature = 0 }
            @{ Name = 'has no such attributes'; Enrollment = $null; Signature = $null }
        ) {
            $template = Get-TemplateFixture -EnrollmentFlag $Enrollment -RaSignature $Signature

            (Get-Selected -Template @($template))[0].ApprovalRequired | Should -Be $false
        }
    }

    Context 'a template without attributes' {
        It 'is dropped without an error' {
            $bare = [PSCustomObject]@{ DistinguishedName = 'CN=Bare,CN=x'; Name = 'Bare' }

            Get-Selected -Template @($bare, (Get-TemplateFixture -Name 'Kept')) |
                ForEach-Object { $_.Name } | Should -Be @('Kept')
        }
    }

    Context 'result' {
        It 'returns the name and distinguished name of each kept template, in order' {
            $result = Get-Selected -Template @(
                Get-TemplateFixture -Name 'B'
                Get-TemplateFixture -Name 'Drop' -NameFlag 0
                Get-TemplateFixture -Name 'A'
            )

            @($result.Name) | Should -Be @('B', 'A')
            $result[0].DistinguishedName | Should -BeExactly (
                'CN=B,CN=Certificate Templates,CN=Public Key Services')
        }

        It 'returns nothing for no templates' {
            Get-Selected -Template @() | Should -BeNullOrEmpty
        }
    }
}
