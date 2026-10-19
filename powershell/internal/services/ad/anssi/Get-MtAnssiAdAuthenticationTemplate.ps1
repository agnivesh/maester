function Get-MtAnssiAdAuthenticationTemplate {
    <#
    .SYNOPSIS
    Selects the certificate templates that let the requester name a certificate used to log on.

    .DESCRIPTION
    Keeps a template when both of these hold, as ANSSI describes the finding. The requester can
    supply the name: msPKI-Certificate-Name-Flag has the subject bit (0x1) or the subject
    alternative name bit (0x10000). The certificate can be used to log on to Windows: the
    pKIExtendedKeyUsage list holds Client Authentication, PKINIT Client Authentication, Smart
    Card Logon or Any Purpose, or is empty, which places no restriction on the use. A template
    without the name flags attribute is left out. Each kept template also says whether it needs
    an approval before a certificate is issued: the enrollment flags ask the CA to hold all
    requests (0x2) or the template asks for authorized signatures (msPKI-RA-Signature above 0).

    .PARAMETER Template
    The certificate template objects, with the attributes msPKI-Certificate-Name-Flag,
    pKIExtendedKeyUsage, msPKI-Enrollment-Flag and msPKI-RA-Signature in their Attribute
    dictionary.

    .EXAMPLE
    Get-MtAnssiAdAuthenticationTemplate -Template $templates

    Returns the DistinguishedName, Name and ApprovalRequired of each template to judge.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Template
    )

    $logon = '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0'
    foreach ($item in $Template) {
        $attribute = $item.Attribute
        if ($null -eq $attribute) { continue }
        $nameFlag = $attribute['msPKI-Certificate-Name-Flag'] -as [int64]
        if (($nameFlag -band 0x10001) -eq 0) { continue }
        $usage = @($attribute['pKIExtendedKeyUsage'] | Where-Object { $_ })
        $restricted = $usage.Count -gt 0
        if ($restricted -and @($usage | Where-Object { $logon -contains $_ }).Count -eq 0) {
            continue
        }
        $holdsRequests = (($attribute['msPKI-Enrollment-Flag'] -as [int64]) -band 2) -ne 0
        $signed = ($attribute['msPKI-RA-Signature'] -as [int64]) -gt 0
        [PSCustomObject]@{
            DistinguishedName = $item.DistinguishedName
            Name              = $item.Name
            ApprovalRequired  = $holdsRequests -or $signed
        }
    }
}
