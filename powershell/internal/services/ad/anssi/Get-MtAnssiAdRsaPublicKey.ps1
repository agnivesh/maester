function Get-MtAnssiAdRsaPublicKey {
    <#
    .SYNOPSIS
    Reads the modulus and the public exponent of a DER-encoded RSA public key.

    .DESCRIPTION
    Decodes an RSAPublicKey structure (RFC 8017: a SEQUENCE of the modulus and the public
    exponent, both INTEGER), which is the content of the public key of an RSA certificate.
    Returns the modulus bytes without leading zero bytes, its length in bits and the exponent.
    An exponent too large for 64 bits is returned as [uint64]::MaxValue. Throws when the data
    is not such a structure.

    .PARAMETER Key
    The DER-encoded RSAPublicKey.

    .EXAMPLE
    Get-MtAnssiAdRsaPublicKey -Key $certificate.PublicKey.EncodedKeyValue.RawData

    Returns Modulus, BitLength and Exponent.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Key
    )

    $outer = @(Get-MtAnssiAdDerElement -Byte $Key)
    if ((@($outer.Tag) -join ',') -ne '48') { throw 'The RSA public key is not a SEQUENCE.' }
    $part = @(Get-MtAnssiAdDerElement -Byte $Key -Offset $outer[0].ContentOffset)
    if ((@($part | Select-Object -First 2 | ForEach-Object Tag) -join ',') -ne '2,2') {
        throw 'The RSA public key does not hold a modulus and an exponent.'
    }

    $start = $part[0].ContentOffset
    while ($Key[$start] -eq 0) { $start++ }
    $modulus = [byte[]]@()
    $bitLength = 0
    if ($start -lt $part[0].End) {
        $modulus = [byte[]]$Key[$start..($part[0].End - 1)]
        $bitLength = ($modulus.Length - 1) * 8 + [Convert]::ToString($modulus[0], 2).Length
    }

    $exponent = [uint64]0
    for ($index = $part[1].ContentOffset; $index -lt $part[1].End; $index++) {
        if ($exponent -gt [uint64]0x00FFFFFFFFFFFFFF) {
            $exponent = [uint64]::MaxValue
            break
        }
        $exponent = $exponent * [uint64]256 + [uint64]$Key[$index]
    }

    [PSCustomObject]@{
        Modulus   = $modulus
        BitLength = $bitLength
        Exponent  = $exponent
    }
}
