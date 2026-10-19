BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-SDer {
        param([int] $Tag, [object[]] $Part = @())
        $content = [System.Collections.Generic.List[byte]]::new()
        foreach ($item in $Part) { foreach ($value in $item) { $content.Add([byte]$value) } }
        [byte[]](@($Tag, $content.Count) + $content.ToArray())
    }

    function Get-SOid {
        param([string] $Dotted)
        $arc = @($Dotted.Split('.') | ForEach-Object { [long]$_ })
        $bytes = @(40 * $arc[0] + $arc[1])
        foreach ($value in $arc[2..($arc.Count - 1)]) {
            $chunk = @($value -band 0x7F)
            $value = $value -shr 7
            while ($value -gt 0) {
                $chunk = @(($value -band 0x7F) -bor 0x80) + $chunk
                $value = $value -shr 7
            }
            $bytes += $chunk
        }
        Get-SDer -Tag 0x06 -Part @(, $bytes)
    }

    # A certificate reduced to what the signature check reads: an empty TBS part, the signature
    # algorithm with optional RSASSA-PSS parameters, and a signature value.
    function Get-SigCert {
        param([string] $Algorithm, [object[]] $PssField)
        $identifier = @(, (Get-SOid -Dotted $Algorithm))
        if ($null -ne $PssField) { $identifier += , (Get-SDer -Tag 0x30 -Part $PssField) }
        $signature = Get-SDer -Tag 0x30 -Part $identifier
        [byte[]](Get-SDer -Tag 0x30 -Part @((Get-SDer -Tag 0x30), $signature,
                (Get-SDer -Tag 0x03 -Part @(, @(0, 1)))))
    }

    function Get-PssHash {
        param([string] $Hash)
        $identifier = Get-SDer -Tag 0x30 -Part @((Get-SOid -Dotted $Hash), @(5, 0))
        Get-SDer -Tag 0xA0 -Part @(, $identifier)
    }

    function Test-Signature {
        param([byte[]] $Certificate, [string] $Algorithm)
        InModuleScope Maester -Parameters @{ Certificate = $Certificate; Algorithm = $Algorithm } {
            param($Certificate, $Algorithm)
            Get-MtAnssiAdSignatureWeakness -Certificate $Certificate -Algorithm $Algorithm
        }
    }
}

Describe 'Get-MtAnssiAdSignatureWeakness' {
    It 'accepts <Name>' -ForEach @(
        @{ Name = 'sha256WithRSA'; Oid = '1.2.840.113549.1.1.11' }
        @{ Name = 'sha384WithRSA'; Oid = '1.2.840.113549.1.1.12' }
        @{ Name = 'sha512WithRSA'; Oid = '1.2.840.113549.1.1.13' }
        @{ Name = 'sha224WithRSA'; Oid = '1.2.840.113549.1.1.14' }
        @{ Name = 'sha512-224WithRSA'; Oid = '1.2.840.113549.1.1.15' }
        @{ Name = 'sha512-256WithRSA'; Oid = '1.2.840.113549.1.1.16' }
        @{ Name = 'ecdsa-with-SHA224'; Oid = '1.2.840.10045.4.3.1' }
        @{ Name = 'ecdsa-with-SHA256'; Oid = '1.2.840.10045.4.3.2' }
        @{ Name = 'ecdsa-with-SHA384'; Oid = '1.2.840.10045.4.3.3' }
        @{ Name = 'ecdsa-with-SHA512'; Oid = '1.2.840.10045.4.3.4' }
        @{ Name = 'Ed25519'; Oid = '1.3.101.112' }
        @{ Name = 'Ed448'; Oid = '1.3.101.113' }
        @{ Name = 'dsa-with-sha224'; Oid = '2.16.840.1.101.3.4.3.1' }
        @{ Name = 'dsa-with-sha3-224'; Oid = '2.16.840.1.101.3.4.3.5' }
        @{ Name = 'ecdsa-with-sha3-256'; Oid = '2.16.840.1.101.3.4.3.10' }
        @{ Name = 'rsa-with-sha3-512'; Oid = '2.16.840.1.101.3.4.3.16' }
    ) {
        Test-Signature -Certificate ([byte[]](1)) -Algorithm $Oid | Should -Be $false
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'md2WithRSA'; Oid = '1.2.840.113549.1.1.2' }
        @{ Name = 'md5WithRSA'; Oid = '1.2.840.113549.1.1.4' }
        @{ Name = 'sha1WithRSA'; Oid = '1.2.840.113549.1.1.5' }
        @{ Name = 'dsa-with-sha1'; Oid = '1.2.840.10040.4.3' }
        @{ Name = 'ecdsa-with-SHA1'; Oid = '1.2.840.10045.4.1' }
        @{ Name = 'an arc after the SHA-3 signatures'; Oid = '2.16.840.1.101.3.4.3.17' }
        @{ Name = 'an empty algorithm'; Oid = '' }
    ) {
        Test-Signature -Certificate ([byte[]](1)) -Algorithm $Oid | Should -Be $true
    }

    It 'reads the hash of an RSASSA-PSS signature: <Name> is weak: <Weak>' -ForEach @(
        @{ Name = 'SHA-256'; Hash = '2.16.840.1.101.3.4.2.1'; Weak = $false }
        @{ Name = 'SHA-512'; Hash = '2.16.840.1.101.3.4.2.3'; Weak = $false }
        @{ Name = 'SHA3-224'; Hash = '2.16.840.1.101.3.4.2.7'; Weak = $false }
        @{ Name = 'SHA3-512'; Hash = '2.16.840.1.101.3.4.2.10'; Weak = $false }
        @{ Name = 'SHAKE128'; Hash = '2.16.840.1.101.3.4.2.11'; Weak = $true }
        @{ Name = 'SHA-1'; Hash = '1.3.14.3.2.26'; Weak = $true }
        @{ Name = 'MD5'; Hash = '1.2.840.113549.2.5'; Weak = $true }
        @{ Name = 'an AES arc'; Hash = '2.16.840.1.101.3.4.1.2'; Weak = $true }
        @{ Name = 'a SHA-2 arc with an extra arc'; Hash = '2.16.840.1.101.3.4.2.1.1'; Weak = $true }
    ) {
        $field = @(, (Get-PssHash -Hash $Hash))
        $certificate = Get-SigCert -Algorithm '1.2.840.113549.1.1.10' -PssField $field

        Test-Signature -Certificate $certificate -Algorithm '1.2.840.113549.1.1.10' |
            Should -Be $Weak
    }

    It 'finds the PSS hash among the other parameters' {
        $field = @((Get-PssHash -Hash '2.16.840.1.101.3.4.2.2'), (Get-SDer -Tag 0xA2 `
            -Part @(, (2, 1, 32))))
        $certificate = Get-SigCert -Algorithm '1.2.840.113549.1.1.10' -PssField $field

        Test-Signature -Certificate $certificate -Algorithm '1.2.840.113549.1.1.10' |
            Should -Be $false
    }

    It 'treats a PSS signature without a hash as SHA-1, the default: <Name>' -ForEach @(
        @{ Name = 'no parameter field'; Kind = 'none' }
        @{ Name = 'empty parameters'; Kind = 'empty' }
        @{ Name = 'only a salt length'; Kind = 'salt' }
    ) {
        $field = switch ($Kind) {
            'none' { $null }
            'empty' { , @() }
            'salt' { @(, (Get-SDer -Tag 0xA2 -Part @(, (2, 1, 32)))) }
        }
        $certificate = Get-SigCert -Algorithm '1.2.840.113549.1.1.10' -PssField $field

        Test-Signature -Certificate $certificate -Algorithm '1.2.840.113549.1.1.10' |
            Should -Be $true
    }

    It 'throws when the PSS parameters cannot be read' {
        { Test-Signature -Certificate ([byte[]](0x30, 0x05, 0x01)) `
            -Algorithm '1.2.840.113549.1.1.10' } |
            Should -Throw -ExpectedMessage '*DER*'
    }
}
