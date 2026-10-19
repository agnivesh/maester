BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-KDer {
        param([int] $Tag, [object[]] $Part = @())
        $content = [System.Collections.Generic.List[byte]]::new()
        foreach ($item in $Part) { foreach ($value in $item) { $content.Add([byte]$value) } }
        $header = @($Tag)
        if ($content.Count -ge 128) {
            $header += 0x82, ($content.Count -shr 8), ($content.Count -band 0xFF)
        } else {
            $header += $content.Count
        }
        [byte[]]($header + $content.ToArray())
    }

    function Get-Key {
        param([byte[]] $Modulus, [byte[]] $Exponent)
        [byte[]](Get-KDer -Tag 0x30 -Part @((Get-KDer -Tag 2 -Part @(, $Modulus)),
                (Get-KDer -Tag 2 -Part @(, $Exponent))))
    }

    function Read-Key {
        param([byte[]] $Key)
        InModuleScope Maester -Parameters @{ Key = $Key } {
            param($Key)
            Get-MtAnssiAdRsaPublicKey -Key $Key
        }
    }
}

Describe 'Get-MtAnssiAdRsaPublicKey' {
    It 'returns the modulus without its sign byte, its bit length and the exponent' {
        $modulus = [byte[]](@(0x00, 0x80) + @(0x11) * 127)

        $key = Read-Key -Key (Get-Key -Modulus $modulus -Exponent ([byte[]](1, 0, 1)))

        $key.BitLength | Should -Be 1024
        $key.Modulus.Length | Should -Be 128
        $key.Modulus[0] | Should -Be 0x80
        $key.Modulus[127] | Should -Be 0x11
        $key.Exponent | Should -Be 65537
        $key.Exponent | Should -BeOfType [uint64]
    }

    It 'counts the bits of the first byte: <First> gives <Bits> bits' -ForEach @(
        @{ First = 0x01; Bits = 1017 }
        @{ First = 0x7F; Bits = 1023 }
        @{ First = 0xFF; Bits = 1024 }
    ) {
        $modulus = [byte[]](@($First) + @(0x22) * 127)

        (Read-Key -Key (Get-Key -Modulus $modulus -Exponent ([byte[]]@(3)))).BitLength |
            Should -Be $Bits
    }

    It 'returns an empty modulus of 0 bits when it is zero' {
        $key = Read-Key -Key (Get-Key -Modulus ([byte[]](0, 0)) -Exponent ([byte[]]@(3)))

        $key.BitLength | Should -Be 0
        $key.Modulus.Length | Should -Be 0
    }

    It 'reads an exponent of <Name>' -ForEach @(
        @{ Name = 'one byte'; Exponent = @(3); Expected = [uint64]3 }
        @{ Name = 'eight bytes'; Exponent = @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x12)
            Expected = [uint64]::MaxValue - 0xED }
        @{ Name = 'nine bytes with a sign byte'; Exponent = @(0, 1, 0, 0, 0, 0, 0, 0, 0)
            Expected = [uint64]72057594037927936 }
        @{ Name = 'nine significant bytes'; Exponent = @(1, 0, 0, 0, 0, 0, 0, 0, 0)
            Expected = [uint64]::MaxValue }
    ) {
        $key = Read-Key -Key (Get-Key -Modulus ([byte[]](0x80, 1)) -Exponent ([byte[]]$Exponent))

        $key.Exponent | Should -Be $Expected
        $key.Exponent | Should -BeOfType [uint64]
    }

    It 'throws when <Case>' -ForEach @(
        @{ Case = 'the key is not a SEQUENCE'; Key = @(0x04, 0x02, 0x02, 0x00) }
        @{ Case = 'two elements follow'; Key = @(0x30, 0x00, 0x30, 0x00) }
        @{ Case = 'the exponent is missing'; Key = @(0x30, 0x03, 0x02, 0x01, 0x05) }
        @{
            Case = 'the modulus is not an INTEGER'
            Key = @(0x30, 0x06, 0x04, 0x01, 0x05, 0x02, 0x01, 0x03)
        }
        @{
            Case = 'the exponent is not an INTEGER'
            Key = @(0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0x03)
        }
        @{ Case = 'the data is empty'; Key = @() }
        @{ Case = 'the key is a SET'; Key = @(0x31, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03) }
        @{
            Case = 'a second SEQUENCE follows'
            Key = @(0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00)
        }
    ) {
        { Read-Key -Key ([byte[]]$Key) } | Should -Throw
    }
}
