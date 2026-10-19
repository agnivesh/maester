function Get-MtAnssiAdCertificateProblem {
    <#
    .SYNOPSIS
    Describes a DER-encoded certificate and lists its weaknesses, each with its ANSSI level.

    .DESCRIPTION
    Level 1: a DSA key, an RSA key under 1024 bits or with the ROCA fingerprint. Level 2: a
    certificate that cannot be parsed. Level 3: an RSA key under 2048 bits, a public exponent
    under 65537, a signature hash other than SHA-2 or SHA-3. Elliptic curve keys are not judged
    beyond their signature. Returns Subject, NotAfter (UTC), Key, Problem (the problem texts),
    and Level (the most severe level, $null when there is no problem).

    .PARAMETER Certificate
    The DER-encoded certificate.

    .EXAMPLE
    Get-MtAnssiAdCertificateProblem -Certificate $bytes

    Returns one object describing the certificate.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Certificate
    )

    $subject = ''
    $notAfter = $null
    $keyName = ''
    try {
        $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate)
        $subject = $x509.Subject
        $notAfter = $x509.NotAfter.ToUniversalTime()
        $keyOid = $x509.PublicKey.Oid.Value
        $keyName = $x509.PublicKey.Oid.FriendlyName
        $problem = @(
            if ($keyOid -eq '1.2.840.10040.4.1') {
                [PSCustomObject]@{ Text = 'DSA key'; Level = 1 }
            }
            if ($keyOid -in @('1.2.840.113549.1.1.1', '1.2.840.113549.1.1.10')) {
                Get-MtAnssiAdRsaKeyProblem -Key $x509.PublicKey.EncodedKeyValue.RawData
            }
            $algorithm = $x509.SignatureAlgorithm
            $weak = Get-MtAnssiAdSignatureWeakness -Certificate $Certificate `
                -Algorithm $algorithm.Value
            if ($weak) {
                $hashName = $algorithm.FriendlyName
                if (-not $hashName) { $hashName = $algorithm.Value }
                [PSCustomObject]@{ Text = "Signature $hashName, not SHA-2 or SHA-3"; Level = 3 }
            }
        )
    } catch {
        $problem = @([PSCustomObject]@{ Text = 'The certificate cannot be parsed'; Level = 2 })
    }

    $level = $null
    if ($problem.Count -gt 0) {
        $level = [int]($problem.Level | Measure-Object -Minimum).Minimum
    }
    [PSCustomObject]@{
        Subject  = $subject
        NotAfter = $notAfter
        Key      = $keyName
        Problem  = [string[]]@(foreach ($item in $problem) { $item.Text })
        Level    = $level
    }
}
