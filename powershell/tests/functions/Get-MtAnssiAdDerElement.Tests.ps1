BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Element {
        param([byte[]] $Data, [int] $Offset = 0, [int] $End = -1)
        InModuleScope Maester -Parameters @{ Data = $Data; Offset = $Offset; End = $End } {
            param($Data, $Offset, $End)
            @(Get-MtAnssiAdDerElement -Byte $Data -Offset $Offset -End $End)
        }
    }

    function Format-Element {
        param([object[]] $Element)
        $text = foreach ($item in $Element) {
            "$($item.Tag):$($item.ContentOffset):$($item.Length):$($item.End)"
        }
        $text -join ' '
    }
}

Describe 'Get-MtAnssiAdDerElement' {
    It 'reads consecutive elements with short lengths' {
        $data = [byte[]](0x30, 0x03, 0x02, 0x01, 0x05, 0x04, 0x00)

        Format-Element (Get-Element -Data $data) | Should -BeExactly '48:2:3:5 4:7:0:7'
    }

    It 'reads the children of an element from its content range' {
        $data = [byte[]](0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07)

        Format-Element (Get-Element -Data $data -Offset 2 -End 8) |
            Should -BeExactly '2:4:1:5 2:7:1:8'
    }

    It 'reads a length of <Size> bytes' -ForEach @(
        @{ Size = 1; Header = @(0x81, 0x80); Length = 128 }
        @{ Size = 2; Header = @(0x82, 0x01, 0x02); Length = 258 }
        @{ Size = 4; Header = @(0x84, 0x00, 0x00, 0x01, 0x01); Length = 257 }
    ) {
        $data = [byte[]](@(0x04) + $Header + @(0xAA) * $Length)

        $element = @(Get-Element -Data $data)

        $element.Count | Should -Be 1
        $element[0].Length | Should -Be $Length
        $element[0].ContentOffset | Should -Be (1 + $Header.Count)
        $element[0].End | Should -Be $data.Length
    }

    It 'returns nothing for an empty range' {
        @(Get-Element -Data ([byte[]]@())).Count | Should -Be 0
        @(Get-Element -Data ([byte[]](0x05, 0x00)) -Offset 2).Count | Should -Be 0
    }

    It 'stops at the end of the range, not the end of the data' {
        $data = [byte[]](0x05, 0x00, 0x05, 0x00)

        @(Get-Element -Data $data -End 2).Count | Should -Be 1
    }

    It 'throws when <Case>' -ForEach @(
        @{ Case = 'the header is cut'; Data = @(0x30) }
        @{ Case = 'the content is cut'; Data = @(0x30, 0x03, 0x01, 0x02) }
        @{ Case = 'the length is indefinite'; Data = @(0x30, 0x80, 0x00, 0x00) }
        @{ Case = 'the length takes 5 bytes'; Data = @(0x04, 0x85, 0, 0, 0, 0, 1, 0xAA) }
        @{ Case = 'the length bytes are cut'; Data = @(0x04, 0x82, 0x01) }
        @{ Case = 'the long length is cut'; Data = @(0x04, 0x81, 0x02, 0xAA) }
    ) {
        { Get-Element -Data ([byte[]]$Data) } | Should -Throw -ExpectedMessage '*DER*'
    }

    It 'throws for an indefinite length even when enough bytes follow' {
        $data = [byte[]](@(0x04, 0x80) + @(0xAA) * 128)

        { Get-Element -Data $data } | Should -Throw -ExpectedMessage '*cannot be read*'
    }

    It 'throws when an element runs past the end of the range' {
        $data = [byte[]](0x30, 0x02, 0x05, 0x00, 0x05, 0x00)

        { Get-Element -Data $data -Offset 0 -End 3 } | Should -Throw -ExpectedMessage '*truncated*'
    }
}
