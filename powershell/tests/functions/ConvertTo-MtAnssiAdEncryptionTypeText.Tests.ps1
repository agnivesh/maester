BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Text {
        param([AllowNull()] [object] $Value)
        InModuleScope Maester -Parameters @{ Value = $Value } {
            param($Value)
            ConvertTo-MtAnssiAdEncryptionTypeText -Value $Value
        }
    }
}

Describe 'ConvertTo-MtAnssiAdEncryptionTypeText' {
    It 'describes <Value>' -ForEach @(
        @{ Value = 1; Expected = 'DES-CBC-CRC (0x1)' }
        @{ Value = 2; Expected = 'DES-CBC-MD5 (0x2)' }
        @{ Value = 4; Expected = 'RC4 (0x4)' }
        @{ Value = 8; Expected = 'AES128 (0x8)' }
        @{ Value = 16; Expected = 'AES256 (0x10)' }
        @{ Value = 24; Expected = 'AES128, AES256 (0x18)' }
        @{ Value = 28; Expected = 'RC4, AES128, AES256 (0x1C)' }
        @{ Value = 36; Expected = 'RC4, AES session keys (0x24)' }
        @{ Value = 31; Expected = 'DES-CBC-CRC, DES-CBC-MD5, RC4, AES128, AES256 (0x1F)' }
        @{ Value = 56; Expected = 'AES128, AES256, AES session keys (0x38)' }
    ) {
        Get-Text -Value $Value | Should -BeExactly $Expected
    }

    It 'says not set for null, zero and text that is not a number' {
        Get-Text -Value $null | Should -BeExactly 'Not set'
        Get-Text -Value 0 | Should -BeExactly 'Not set'
        Get-Text -Value '0' | Should -BeExactly 'Not set'
        Get-Text -Value 'abc' | Should -BeExactly 'Not set'
    }

    It 'reads a value given as text' {
        Get-Text -Value '28' | Should -BeExactly 'RC4, AES128, AES256 (0x1C)'
    }

    It 'mentions bits it does not know' {
        Get-Text -Value 68 | Should -BeExactly 'RC4, other bits (0x44)'
    }
}
