function Get-MtAnssiAdSignatureWeakness {
    <#
    .SYNOPSIS
    Tells whether a certificate is signed with a hash other than SHA-2 or SHA-3.

    .DESCRIPTION
    Compares the signature algorithm of the certificate with the RSA, ECDSA, DSA and EdDSA
    signature algorithms based on SHA-2 or SHA-3 (OIDs from RFC 4055, RFC 5758, RFC 8692, NIST
    CSOR and RFC 8410). For RSASSA-PSS the hash is read from the algorithm parameters of the
    certificate; with no hash given, PSS uses SHA-1 (RFC 4055). Anything else, MD5 and SHA-1
    included, is weak. Throws when the parameters of a PSS signature cannot be read.

    .PARAMETER Certificate
    The DER-encoded certificate.

    .PARAMETER Algorithm
    The OID of the signature algorithm, as X509Certificate2.SignatureAlgorithm.Value gives it.

    .EXAMPLE
    Get-MtAnssiAdSignatureWeakness -Certificate $bytes -Algorithm '1.2.840.113549.1.1.5'

    Returns $true: SHA-1 with RSA.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Certificate,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Algorithm
    )

    $strong = @(
        '1.2.840.113549.1.1.11', '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13',
        '1.2.840.113549.1.1.14', '1.2.840.113549.1.1.15', '1.2.840.113549.1.1.16',
        '1.2.840.10045.4.3.1', '1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4',
        '1.3.101.112', '1.3.101.113')
    foreach ($last in 1..16) { $strong += "2.16.840.1.101.3.4.3.$last" }
    if ($Algorithm -in $strong) { return $false }
    if ($Algorithm -ne '1.2.840.113549.1.1.10') { return $true }

    $outer = @(Get-MtAnssiAdDerElement -Byte $Certificate)[0]
    $signature = @(Get-MtAnssiAdDerElement -Byte $Certificate -Offset $outer.ContentOffset `
            -End $outer.End)[1]
    $parameter = @(Get-MtAnssiAdDerElement -Byte $Certificate -Offset $signature.ContentOffset `
            -End $signature.End)[1]
    $field = @(Get-MtAnssiAdDerElement -Byte $Certificate -Offset $parameter.ContentOffset `
            -End $parameter.End)
    $hash = @($field | Where-Object { $_.Tag -eq 0xA0 })
    if ($hash.Count -eq 0) { return $true }

    $identifier = @(Get-MtAnssiAdDerElement -Byte $Certificate -Offset $hash[0].ContentOffset `
            -End $hash[0].End)[0]
    $oid = @(Get-MtAnssiAdDerElement -Byte $Certificate -Offset $identifier.ContentOffset `
            -End $identifier.End)[0]
    $text = [BitConverter]::ToString($Certificate, $oid.ContentOffset, $oid.Length)
    return $text -notmatch '^60-86-48-01-65-03-04-02-(0[1-9]|0A)$'
}
