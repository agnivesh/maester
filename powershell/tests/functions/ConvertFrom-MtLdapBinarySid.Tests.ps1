BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Sid {
        param([byte[]] $Bytes, [int] $Offset = 0)
        InModuleScope Maester -Parameters @{ Bytes = $Bytes; Offset = $Offset } {
            param($Bytes, $Offset)
            ConvertFrom-MtLdapBinarySid -Bytes $Bytes -Offset $Offset
        }
    }
}

Describe 'ConvertFrom-MtLdapBinarySid' {
    It 'reads a domain SID' {
        $bytes = [byte[]](1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0,
            0x51, 0x04, 0, 0)

        Get-Sid -Bytes $bytes | Should -BeExactly 'S-1-5-21-1-2-3-1105'
    }

    It 'reads a SID at an offset' {
        $bytes = [byte[]](9, 9, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0)

        Get-Sid -Bytes $bytes -Offset 2 | Should -BeExactly 'S-1-5-32-544'
    }

    It 'reads the identifier authority as a big-endian number' {
        $bytes = [byte[]](1, 1, 0, 0, 0, 0, 0x01, 0x00, 0, 0x30, 0, 0)

        Get-Sid -Bytes $bytes | Should -BeExactly 'S-1-256-12288'
    }

    It 'reads a SID without sub-authority' {
        Get-Sid -Bytes ([byte[]](1, 0, 0, 0, 0, 0, 0, 1)) | Should -BeExactly 'S-1-1'
    }

    It 'throws when the header does not fit' {
        { Get-Sid -Bytes ([byte[]](1, 1, 0, 0, 0)) } | Should -Throw '*does not fit*'
    }

    It 'throws when the sub-authorities do not fit' {
        $bytes = [byte[]](1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0)

        { Get-Sid -Bytes $bytes } | Should -Throw '*does not fit*'
    }

    It 'throws for a negative offset even when the bytes would fit' {
        $bytes = [byte[]](0, 1, 0, 0, 0, 0, 0, 0, 1)

        { Get-Sid -Bytes $bytes -Offset -1 } | Should -Throw '*does not fit*'
    }

    It 'reads the revision byte' {
        Get-Sid -Bytes ([byte[]](2, 0, 0, 0, 0, 0, 0, 5)) | Should -BeExactly 'S-2-5'
    }

    It 'throws when the SID starts past the end' {
        $bytes = [byte[]](1, 0, 0, 0, 0, 0, 0, 1)

        { Get-Sid -Bytes $bytes -Offset 8 } | Should -Throw '*does not fit*'
    }
}
