function Get-MtAnssiAdTrustedCaName {
    <#
    .SYNOPSIS
    Finds the CAs whose certificate is in the NTAuthCertificates store.

    .DESCRIPTION
    Windows accepts certificates for logon only from CAs whose certificate is one of the
    certificates of the NTAuthCertificates store (the cACertificate attribute of that object).
    Enterprise CAs add themselves to it. Returns the distinguished names of the objects, other than
    the store itself, that hold one of those certificates, for example the enrollment services.
    Certificates are compared byte for byte, distinguished names without regard to case. When the
    NTAuthCertificates store is not among the certificates (the store is readable by everyone, so
    this means the forest has no enterprise CA), no CA is trusted for logon and the result is
    empty.

    .PARAMETER CaCertificate
    The objects with certificates read from the directory (Get-MtAnssiAdCaCertificate): the
    NTAuthCertificates store, the enrollment services and others.

    .EXAMPLE
    Get-MtAnssiAdTrustedCaName -CaCertificate $certificates

    Returns the set of distinguished names of the CA objects trusted for logon.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]], [object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $CaCertificate
    )

    $inStore = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($store in @($CaCertificate | Where-Object { $_.Name -eq 'NTAuthCertificates' })) {
        foreach ($certificate in $store.Certificate) {
            $null = $inStore.Add([Convert]::ToBase64String($certificate))
        }
    }

    $trusted = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $CaCertificate) {
        if ($item.Name -eq 'NTAuthCertificates') { continue }
        foreach ($certificate in $item.Certificate) {
            if ($inStore.Contains([Convert]::ToBase64String($certificate))) {
                $null = $trusted.Add([string]$item.DistinguishedName)
            }
        }
    }
    return , $trusted
}
