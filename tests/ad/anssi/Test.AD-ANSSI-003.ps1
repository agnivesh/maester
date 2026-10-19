function Test-MtAnssiAdPkiTemplateSuppliedSubject {
    <#
    .SYNOPSIS
    ANSSI-AD-003: Certificate templates should not let requesters name a logon certificate.

    .DESCRIPTION
    Checks that no principal outside the privileged set can enroll in a certificate template that
    lets the requester supply the name of the certificate (the subject or the subject alternative
    name) when that certificate can be used to log on to Windows. Such a template lets anyone who
    can enroll ask a CA for a certificate in the name of another account, a domain administrator
    included, and log on with it.

    The test reads the certificate templates, the enrollment services that publish them, the
    certificates of the CAs and the NTAuthCertificates store of the forest. It reports the
    enrollment rights of untrusted principals on the templates that qualify. ANSSI gives this
    finding level 1 only, so every right is Critical. When a CA that Windows accepts for logon
    publishes a reported template the result says so, because the attack then works today; the
    other templates are reported because they would work as soon as such a CA publishes them. It
    is skipped when a read fails, when Active Directory is not connected, and outside the forest
    root domain.

    .EXAMPLE
    Test-MtAnssiAdPkiTemplateSuppliedSubject

    Returns $true when no untrusted principal can enroll in such a template, $false otherwise, or
    $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPkiTemplateSuppliedSubject
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-003',
        Title = 'Certificate templates should not let requesters name a logon certificate',
        Product = 'ad',
        Feature = 'certificate-services',
        Area = 'access-control',
        ResourceType = 'CertificateAuthority',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1649',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPkiTemplateSuppliedSubject'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID was not found in the collected data.')
        return $null
    }

    if (-not (Get-MtAnssiAdDomainIsForestRoot -Domain $adState.Domain)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'Certificate templates are shared by the whole forest and their default permissions ' +
            'name the Domain Admins of the forest root domain: run this test against the forest ' +
            'root domain.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $trusted = Get-MtAnssiAdTrustedSid -Privileged $privileged -Group $adState.Groups `
        -DomainSid $domainSid
    $assessment = Get-MtAnssiAdSuppliedSubjectAssessment -AdState $adState `
        -TrustedSid $trusted

    $judged = @($assessment.Judged)
    $findings = @($assessment.Finding)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            'No principal outside the privileged set can enroll in the ' +
            "$($judged.Count) certificate templates that let the requester name a certificate " +
            "used to log on.$note")
        return $true
    }

    $templateNote = (Get-MtAnssiAdPublicationNote -Finding $findings) +
        (Get-MtAnssiAdApprovalNote -Finding $findings)
    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) rights to enroll in certificate templates that let the " +
        'requester name a certificate used to log on are held by principals outside the ' +
        "privileged set.$note$templateNote`n`n$table"
    Add-MtTestResultDetail -Result $result
    return $false
}
