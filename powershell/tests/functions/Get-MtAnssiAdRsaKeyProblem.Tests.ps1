BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Problem {
        param([int] $Bits, [uint64] $Exponent = 65537, [bool] $Roca = $false)
        $script:rsa = [PSCustomObject]@{
            Modulus = [byte[]](1, 2, 3); BitLength = $Bits; Exponent = $Exponent
        }
        Mock Get-MtAnssiAdRsaPublicKey -ModuleName Maester -MockWith { $script:rsa }
        $answer = $Roca
        Mock Get-MtAnssiAdRocaFingerprint -ModuleName Maester `
            -MockWith ({ $answer }.GetNewClosure())
        InModuleScope Maester {
            @(Get-MtAnssiAdRsaKeyProblem -Key ([byte[]](9, 9)))
        }
    }

    function Format-Problem {
        param([object[]] $Problem)
        @(foreach ($item in $Problem) { "$($item.Level):$($item.Text)" }) -join ' | '
    }
}

Describe 'Get-MtAnssiAdRsaKeyProblem' {
    It 'gives <Expected> for <Bits> bits, exponent <Exponent>, ROCA <Roca>' -ForEach @(
        @{ Bits = 4096; Exponent = 65537; Roca = $false; Expected = '' }
        @{ Bits = 2048; Exponent = 65537; Roca = $false; Expected = '' }
        @{
            Bits = 2047
            Exponent = 65537
            Roca = $false
            Expected = '3:RSA key of 2047 bits, under 2048'
        }
        @{
            Bits = 1024
            Exponent = 65537
            Roca = $false
            Expected = '3:RSA key of 1024 bits, under 2048'
        }
        @{
            Bits = 1023
            Exponent = 65537
            Roca = $false
            Expected = '1:RSA key of 1023 bits, under 1024'
        }
        @{
            Bits = 2048
            Exponent = 65537
            Roca = $true
            Expected = '1:RSA key with the ROCA weakness'
        }
        @{ Bits = 1024; Exponent = 65537; Roca = $true
            Expected = '1:RSA key with the ROCA weakness | 3:RSA key of 1024 bits, under 2048' }
        @{
            Bits = 2048
            Exponent = 65536
            Roca = $false
            Expected = '3:RSA public exponent 65536, under 65537'
        }
        @{
            Bits = 2048
            Exponent = 3
            Roca = $false
            Expected = '3:RSA public exponent 3, under 65537'
        }
        @{ Bits = 512; Exponent = 3; Roca = $false
            Expected = '1:RSA key of 512 bits, under 1024 | 3:RSA public exponent 3, under 65537' }
    ) {
        Format-Problem (Get-Problem -Bits $Bits -Exponent $Exponent -Roca $Roca) |
            Should -BeExactly $Expected
    }

    It 'tests the modulus for ROCA from 1024 bits on' {
        $null = Get-Problem -Bits 1024

        Should -Invoke Get-MtAnssiAdRocaFingerprint -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { ($Modulus -join ',') -eq '1,2,3' }
    }

    It 'does not test a key under 1024 bits for ROCA' {
        $null = Get-Problem -Bits 1023 -Roca $true

        Should -Invoke Get-MtAnssiAdRocaFingerprint -ModuleName Maester -Times 0 -Exactly
    }

    It 'decodes the key it is given' {
        $null = Get-Problem -Bits 2048

        Should -Invoke Get-MtAnssiAdRsaPublicKey -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { ($Key -join ',') -eq '9,9' }
    }

    It 'lets a key that cannot be decoded throw' {
        Mock Get-MtAnssiAdRsaPublicKey -ModuleName Maester -MockWith { throw 'not a key' }

        { InModuleScope Maester { Get-MtAnssiAdRsaKeyProblem -Key ([byte[]](1)) } } |
            Should -Throw -ExpectedMessage 'not a key'
    }
}
