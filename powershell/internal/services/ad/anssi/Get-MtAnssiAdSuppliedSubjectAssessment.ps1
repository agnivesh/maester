function Get-MtAnssiAdSuppliedSubjectAssessment {
    <#
    .SYNOPSIS
    Reads the PKI objects of the forest and works out the findings of ANSSI-AD-003.

    .DESCRIPTION
    Reads the certificate templates (with the attributes that tell whether the requester names the
    certificate, what it can be used for and whether it needs an approval), the enrollment
    services that publish them, and the certificates of the CAs and of the NTAuthCertificates
    store, all from the Services container of the Configuration partition and cached per session.
    Selects the templates that let the requester name a certificate used to log on, lists who
    outside the trusted set can enroll in them and gives each right its level. Throws when a read
    fails or when the permissions of a selected template cannot be read.

    .PARAMETER AdState
    The collected state, for the protocol evidence used to open the LDAP connection.

    .PARAMETER TrustedSid
    The SIDs whose rights are expected, for example from Get-MtAnssiAdTrustedSid.

    .EXAMPLE
    Get-MtAnssiAdSuppliedSubjectAssessment -AdState $adState -TrustedSid $trusted

    Returns the templates that were judged (Judged) and the findings (Finding).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [object] $AdState,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]] $TrustedSid
    )

    $evidence = $AdState.ProtocolEvidence
    $head = @(Get-MtAnssiAdNamingContextHead -ProtocolEvidence $evidence)
    $configuration = @($head -like 'CN=Configuration,*')[0]
    $services = @($head -like 'CN=Configuration,*' | ForEach-Object { "CN=Services,$_" })
    $attribute = @('msPKI-Certificate-Name-Flag', 'pKIExtendedKeyUsage', 'msPKI-Enrollment-Flag',
        'msPKI-RA-Signature')
    $templates = @(Get-MtAnssiAdSearchSecurity -SearchBase $services -Scope Subtree `
            -Filter '(objectClass=pKICertificateTemplate)' -Attribute $attribute `
            -ProtocolEvidence $evidence)
    $enrollment = @(Get-MtAnssiAdSearchSecurity -SearchBase $services -Scope Subtree `
            -Filter '(objectClass=pKIEnrollmentService)' -Attribute @('certificateTemplates') `
            -ProtocolEvidence $evidence)
    $certificates = @(Get-MtAnssiAdCaCertificate -SearchBase "CN=Services,$configuration" `
            -ProtocolEvidence $evidence)
    $publication = Get-MtAnssiAdTemplatePublication -EnrollmentService $enrollment `
        -CaCertificate $certificates

    $judged = @(Get-MtAnssiAdAuthenticationTemplate -Template $templates)
    $judgedDn = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($judged.DistinguishedName), [System.StringComparer]::OrdinalIgnoreCase)
    $objects = @($templates | Where-Object { $judgedDn.Contains($_.DistinguishedName) })
    $rights = @(Get-MtAnssiAdEnrollmentRight -Object $objects -TrustedSid $TrustedSid)
    return [PSCustomObject]@{
        Judged  = $judged
        Finding = @(Get-MtAnssiAdEnrollmentFinding -Right $rights -Template $judged `
                -Publication $publication)
    }
}
