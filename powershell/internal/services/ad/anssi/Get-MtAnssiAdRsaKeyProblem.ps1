function Get-MtAnssiAdRsaKeyProblem {
    <#
    .SYNOPSIS
    Lists the weaknesses of an RSA public key, each with its ANSSI level.

    .DESCRIPTION
    Level 1: a modulus shorter than 1024 bits, or a modulus with the ROCA fingerprint (tested
    from 1024 bits; a shorter key is already level 1). Level 3: a modulus shorter than 2048 bits,
    or a public exponent below 65537. Returns nothing for a sound key. Throws when the key cannot
    be decoded.

    .PARAMETER Key
    The DER-encoded RSAPublicKey of the certificate.

    .EXAMPLE
    Get-MtAnssiAdRsaKeyProblem -Key $certificate.PublicKey.EncodedKeyValue.RawData

    Returns objects with Text and Level.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Key
    )

    $rsa = Get-MtAnssiAdRsaPublicKey -Key $Key
    if ($rsa.BitLength -lt 1024) {
        [PSCustomObject]@{ Text = "RSA key of $($rsa.BitLength) bits, under 1024"; Level = 1 }
    } else {
        if (Get-MtAnssiAdRocaFingerprint -Modulus $rsa.Modulus) {
            [PSCustomObject]@{ Text = 'RSA key with the ROCA weakness'; Level = 1 }
        }
        if ($rsa.BitLength -lt 2048) {
            [PSCustomObject]@{ Text = "RSA key of $($rsa.BitLength) bits, under 2048"; Level = 3 }
        }
    }
    if ($rsa.Exponent -lt 65537) {
        [PSCustomObject]@{ Text = "RSA public exponent $($rsa.Exponent), under 65537"; Level = 3 }
    }
}
