BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # Two certificates from the ROCA authors' test data (crocs-muni/roca, MIT licence):
    # Let's Encrypt Authority X3 (RSA 2048, SHA-256, not vulnerable) and a self-signed
    # certificate with a key from the vulnerable library (RSA 2050, SHA-256).
    $script:letsEncrypt = [Convert]::FromBase64String(
            'MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/MSQwIgYDVQQKExtEaWdp' +
            'dGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0' +
            'NloXDTIxMDMxNzE2NDA0NlowSjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNV' +
            'BAMTGkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' +
            'nNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EFq6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf' +
            '15Gan/PQeGdxyGkOlZHP/uaZ6WA8SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8j' +
            'KkKQDIZ0Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWAa6xK8xuQSXgv' +
            'opZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj/PIzark5McWvxI0NHWQWM6r6hCm21AvA' +
            '2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUH' +
            'AQEEczBxMDIGCCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNvbTA7Bggr' +
            'BgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9kc3Ryb290Y2F4My5wN2MwHwYDVR0j' +
            'BBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAwVAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEw' +
            'MDAuBggrBgEFBQcCARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAzMDGg' +
            'L6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwuY3JsMB0GA1UdDgQWBBSoSmpj' +
            'BH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsFAAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8Ik' +
            'CJLxWh9KEik3JHRRHGJouM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/' +
            'wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwuX4Po1QYz+3dszkDqMp4f' +
            'klxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlGPfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbG' +
            'S5jN2p8M+X+Q7UNKEkROb3N6KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==')
    $script:rocaKey = [Convert]::FromBase64String(
            'MIICpTCCAYwCCQC2u0PIfFaGMjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTcx' +
            'MDE2MTkzODIxWhcNMTgxMDE2MTkzODIxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB' +
            'AQUAA4IBDwAwggEKAoIBAQJZJ7UrpeaMjJJou5IY83ZzYUymVBj0dFsUPNTuU/lJHJoOHC8jqVFjBq/784Zn' +
            'uHG8DMguYPW7Gp+hWlZxp2XJ8huVh9gBFZZDcqODyIOw3L9sd1cGsx6v8+P9SIVZoIzeog+al8TFm2uKjuyk' +
            'V9SoINSVCfdZM2MCvKGjaQsICRgR+Fjy6M6lpiNVrW4EHRk17aWSibWXaDtz4mV650v/x2Dk1RPMh9uTVZGO' +
            'qgjTmLvl9oNdyHElIRubNrOgvHC5k6bLP30stAYd5z25cslCrfmVW2/kzZDwDQiK7ASvH17/kfIa9e1EYXx9' +
            'uAk/lTZtsmWAxK85neuU+bFBMFvhAgMBAAEwDQYJKoZIhvcNAQELBQADggECAAG7W49CYRUkYAFRGXu3M85M' +
            'KOISyc/kkJ8nbHdV6GxJ05FkoDKbcbZ7nncJiIp2VMAMEIP4bRTJ5U4g4vSZlmCs8BDmV3Ts/tbDCM6eqK+2' +
            'hwjhUnCnmmsLt4xVUeAAsWUHl9AVtjzdoYlm1Kk20QBzNpsvM/gFS5B+duHvTSfELfoq9Pdfvmn2gEXJHe9s' +
            'cO8bfT3fm15zR6AUYsSsxAhup2Rix6jgJ14KGsh6uVm6jhz9aBTBcgx7iMuuP8zUbUE6nryHYXnRcSvuYSes' +
            'TCoFfnL7elrZDak/n0jLfwUD80aWnReJfu9QQGdqdDnSG8lSQ1XPOC7O/hFW9l0TCzOE')

    function Get-Der {
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

    function Get-Oid {
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
        Get-Der -Tag 0x06 -Part @(, $bytes)
    }

    function Get-Name {
        param([string] $CommonName)
        $value = Get-Der -Tag 0x0C -Part @(, [System.Text.Encoding]::UTF8.GetBytes($CommonName))
        Get-Der -Tag 0x30 -Part @(, (Get-Der -Tag 0x31 -Part @(, (Get-Der -Tag 0x30 -Part @(
                            (Get-Oid -Dotted '2.5.4.3'), $value)))))
    }

    function Get-Time {
        param([string] $Text)
        Get-Der -Tag 0x17 -Part @(, [System.Text.Encoding]::ASCII.GetBytes($Text))
    }

    function Get-RsaKeyInfo {
        param(
            [int] $Byte = 256,
            [byte[]] $Exponent = @(1, 0, 1),
            [string] $Oid = '1.2.840.113549.1.1.1'
        )
        $modulus = [byte[]](@(0, 0xC0) + @(0xC0) * ($Byte - 1))
        $key = Get-Der -Tag 0x30 -Part @((Get-Der -Tag 2 -Part @(, $modulus)),
            (Get-Der -Tag 2 -Part @(, $Exponent)))
        Get-Der -Tag 0x30 -Part @((Get-Der -Tag 0x30 -Part @((Get-Oid -Dotted $Oid), @(5, 0))),
            (Get-Der -Tag 0x03 -Part @(@(0), $key)))
    }

    function Get-DsaKeyInfo {
        $parameter = Get-Der -Tag 0x30 -Part @((Get-Der -Tag 2 -Part @(, @(0x7F))),
            (Get-Der -Tag 2 -Part @(, @(0x0B))), (Get-Der -Tag 2 -Part @(, @(2))))
        Get-Der -Tag 0x30 -Part @((Get-Der -Tag 0x30 -Part @((Get-Oid -Dotted '1.2.840.10040.4.1'),
                    $parameter)), (Get-Der -Tag 0x03 -Part @(@(0), (Get-Der -Tag 2 `
                        -Part @(, @(5))))))
    }

    function Get-EcKeyInfo {
        $point = @(4) + @(0x11) * 64
        Get-Der -Tag 0x30 -Part @((Get-Der -Tag 0x30 -Part @((Get-Oid -Dotted '1.2.840.10045.2.1'),
                    (Get-Oid -Dotted '1.2.840.10045.3.1.7'))), (Get-Der -Tag 0x03 `
                        -Part @(@(0), $point)))
    }

    function Get-CertFixture {
        param(
            [byte[]] $KeyInfo,
            [string] $Signature = '1.2.840.113549.1.1.11',
            [string] $CommonName = 'Contoso Root CA',
            [string] $NotAfter = '300101120000Z'
        )
        $algorithm = Get-Der -Tag 0x30 -Part @((Get-Oid -Dotted $Signature), @(5, 0))
        $start = Get-Time -Text '200101000000Z'
        $validity = Get-Der -Tag 0x30 -Part @($start, (Get-Time -Text $NotAfter))
        $name = Get-Name -CommonName $CommonName
        $issuer = Get-Name -CommonName 'Contoso Issuing CA'
        $version = Get-Der -Tag 0xA0 -Part @(, (Get-Der -Tag 2 -Part @(, @(2))))
        $tbs = Get-Der -Tag 0x30 -Part @($version,
            (Get-Der -Tag 2 -Part @(, @(1))), $algorithm, $issuer, $validity, $name, $KeyInfo)
        [byte[]](Get-Der -Tag 0x30 -Part @($tbs, $algorithm, (Get-Der -Tag 0x03 `
            -Part @(, @(0, 1, 2)))))
    }

    function Get-Assessment {
        param([byte[]] $Certificate)
        InModuleScope Maester -Parameters @{ Certificate = $Certificate } {
            param($Certificate)
            Get-MtAnssiAdCertificateProblem -Certificate $Certificate
        }
    }
}

Describe 'Get-MtAnssiAdCertificateProblem' {
    It 'finds no problem in a 2048-bit RSA certificate signed with SHA-256' {
        $result = Get-Assessment -Certificate (Get-CertFixture -KeyInfo (Get-RsaKeyInfo))

        $null -eq $result.Level | Should -Be $true
        @($result.Problem).Count | Should -Be 0
        $result.Subject | Should -BeExactly 'CN=Contoso Root CA'
        $result.Key | Should -BeExactly 'RSA'
    }

    It 'returns the expiry date in UTC' {
        $certificate = Get-CertFixture -KeyInfo (Get-RsaKeyInfo) -NotAfter '190305123456Z'

        $result = Get-Assessment -Certificate $certificate

        $result.NotAfter.Kind | Should -Be ([System.DateTimeKind]::Utc)
        $result.NotAfter.ToString('yyyy-MM-dd HH:mm:ss') | Should -BeExactly '2019-03-05 12:34:56'
    }

    It 'judges a <Name>: <Expected>' -ForEach @(
        @{
            Name = 'DSA key'
            Kind = 'dsa'
            Signature = '2.16.840.1.101.3.4.3.2'
            Expected = '1:DSA key'
        }
        @{ Name = 'RSA key of 512 bits'; Kind = 'rsa64'; Signature = '1.2.840.113549.1.1.11'
            Expected = '1:RSA key of 512 bits, under 1024' }
        @{ Name = 'RSA key of 1024 bits'; Kind = 'rsa128'; Signature = '1.2.840.113549.1.1.11'
            Expected = '3:RSA key of 1024 bits, under 2048' }
        @{ Name = 'RSA key with exponent 3'; Kind = 'exp3'; Signature = '1.2.840.113549.1.1.11'
            Expected = '3:RSA public exponent 3, under 65537' }
        @{ Name = 'RSA-PSS key of 1024 bits'; Kind = 'pss128'; Signature = '1.2.840.113549.1.1.11'
            Expected = '3:RSA key of 1024 bits, under 2048' }
        @{ Name = 'MD5 signature'; Kind = 'rsa'; Signature = '1.2.840.113549.1.1.4'
            Expected = '3:Signature md5RSA, not SHA-2 or SHA-3' }
        @{ Name = 'signature of an unknown algorithm'; Kind = 'rsa'; Signature = '1.2.3.4'
            Expected = '3:Signature 1.2.3.4, not SHA-2 or SHA-3' }
        @{ Name = 'elliptic curve key, SHA-256'; Kind = 'ec'; Signature = '1.2.840.10045.4.3.2'
            Expected = '' }
        @{ Name = 'DSA key signed with SHA-1'; Kind = 'dsa'; Signature = '1.2.840.10040.4.3'
            Expected = '1:DSA key | Signature sha1DSA, not SHA-2 or SHA-3' }
    ) {
        $keyInfo = switch ($Kind) {
            'dsa' { Get-DsaKeyInfo }
            'ec' { Get-EcKeyInfo }
            'rsa' { Get-RsaKeyInfo }
            'rsa64' { Get-RsaKeyInfo -Byte 64 }
            'rsa128' { Get-RsaKeyInfo -Byte 128 }
            'pss128' { Get-RsaKeyInfo -Byte 128 -Oid '1.2.840.113549.1.1.10' }
            'exp3' { Get-RsaKeyInfo -Exponent ([byte[]]@(3)) }
        }

        $result = Get-Assessment -Certificate (Get-CertFixture -KeyInfo $keyInfo `
            -Signature $Signature)

        $text = ''
        if ($null -ne $result.Level) { $text = "$($result.Level):$($result.Problem -join ' | ')" }
        $text | Should -BeExactly $Expected
    }

    It 'reports the most severe level of several problems' {
        $certificate = Get-CertFixture -KeyInfo (Get-RsaKeyInfo -Byte 64 -Exponent ([byte[]]@(3))) `
            -Signature '1.2.840.113549.1.1.5'

        $result = Get-Assessment -Certificate $certificate

        $result.Level | Should -Be 1
        $result.Level | Should -BeOfType [int]
        $result.Problem -join ' | ' | Should -BeExactly ('RSA key of 512 bits, under 1024 | ' +
            'RSA public exponent 3, under 65537 | Signature sha1RSA, not SHA-2 or SHA-3')
    }

    It 'reports a certificate that cannot be parsed at level 2: <Name>' -ForEach @(
        @{ Name = 'random bytes'; Kind = 'random' }
        @{ Name = 'no bytes'; Kind = 'empty' }
        @{ Name = 'an RSA key that is not an RSAPublicKey'; Kind = 'badkey' }
    ) {
        $certificate = switch ($Kind) {
            'random' { [byte[]](1, 2, 3, 4) }
            'empty' { , [byte[]]@() }
            'badkey' {
                $keyInfo = Get-Der -Tag 0x30 -Part @((Get-Der -Tag 0x30 -Part @(
                            (Get-Oid -Dotted '1.2.840.113549.1.1.1'), @(5, 0))),
                    (Get-Der -Tag 0x03 -Part @(, @(0, 4, 1, 9))))
                Get-CertFixture -KeyInfo $keyInfo
            }
        }

        $result = Get-Assessment -Certificate $certificate

        $result.Level | Should -Be 2
        $result.Problem -join ' | ' | Should -BeExactly 'The certificate cannot be parsed'
    }

    It 'keeps the subject of a certificate whose key cannot be decoded' {
        $keyInfo = Get-Der -Tag 0x30 -Part @((Get-Der -Tag 0x30 -Part @(
                    (Get-Oid -Dotted '1.2.840.113549.1.1.1'), @(5, 0))), (Get-Der -Tag 0x03 `
                        -Part @(, @(0, 5, 0))))

        $result = Get-Assessment -Certificate (Get-CertFixture -KeyInfo $keyInfo `
            -CommonName 'Broken')

        $result.Subject | Should -BeExactly 'CN=Broken'
        $result.Level | Should -Be 2
    }

    It 'finds the ROCA weakness in a key from the vulnerable library' {
        $result = Get-Assessment -Certificate $script:rocaKey

        $result.Level | Should -Be 1
        $result.Problem -join ' | ' | Should -BeExactly 'RSA key with the ROCA weakness'
        $result.Subject | Should -BeExactly 'CN=localhost'
    }

    It 'finds no problem in the Let''s Encrypt X3 certificate, expired since 2021' {
        $result = Get-Assessment -Certificate $script:letsEncrypt

        $null -eq $result.Level | Should -Be $true
        $result.NotAfter.ToString('yyyy-MM-dd') | Should -BeExactly '2021-03-17'
        $result.Subject | Should -Match '^CN=Let''s Encrypt Authority X3,'
    }
}
