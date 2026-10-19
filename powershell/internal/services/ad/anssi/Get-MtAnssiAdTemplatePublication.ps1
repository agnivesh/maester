function Get-MtAnssiAdTemplatePublication {
    <#
    .SYNOPSIS
    Finds the certificate templates that CAs publish, and those that a CA trusted for logon does.

    .DESCRIPTION
    A template is published when the certificateTemplates attribute of an enrollment service names
    it, so that CA issues certificates from it. It is also trusted when that CA is trusted for
    logon, which Get-MtAnssiAdTrustedCaName decides from the NTAuthCertificates store; the CA is
    found by the distinguished name of its enrollment service. Template names are compared without
    regard to case. Without an NTAuthCertificates store no CA is trusted for logon.

    .PARAMETER EnrollmentService
    The enrollment service objects, with certificateTemplates in their Attribute dictionary.

    .PARAMETER CaCertificate
    The objects with certificates read from the directory (Get-MtAnssiAdCaCertificate): the
    NTAuthCertificates store and the enrollment services.

    .EXAMPLE
    Get-MtAnssiAdTemplatePublication -EnrollmentService $services -CaCertificate $certificates

    Returns the Published and Trusted sets of template names.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $EnrollmentService,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $CaCertificate
    )

    $trustedCa = Get-MtAnssiAdTrustedCaName -CaCertificate $CaCertificate
    $ignoreCase = [System.StringComparer]::OrdinalIgnoreCase
    $published = [System.Collections.Generic.HashSet[string]]::new($ignoreCase)
    $trusted = [System.Collections.Generic.HashSet[string]]::new($ignoreCase)
    foreach ($service in $EnrollmentService) {
        $isTrusted = $trustedCa.Contains([string]$service.DistinguishedName)
        foreach ($name in $service.Attribute['certificateTemplates']) {
            $null = $published.Add([string]$name)
            if ($isTrusted) { $null = $trusted.Add([string]$name) }
        }
    }
    return [PSCustomObject]@{ Published = $published; Trusted = $trusted }
}
