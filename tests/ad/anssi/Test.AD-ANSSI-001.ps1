function Test-MtAnssiAdPkiAuthorityControl {
    <#
    .SYNOPSIS
    ANSSI-AD-001: Only privileged principals should control the certification authorities.

    .DESCRIPTION
    Checks that no principal outside the privileged set holds a dangerous right on the certificate
    containers and CA objects of the forest (below CN=Public Key Services in the Configuration
    partition). With such a right an attacker can add a malicious certification authority, or
    list one as trusted for logon, and then authenticate as any user or service.

    The test reads the owner and permissions of the containers, the certification authority
    objects, the NTAuthCertificates store, the enrollment services, the CRL distribution points
    and the key recovery agents, and reports the owner and the rights to take over, change or add
    children to them. A default CA installation is expected: the Cert Publishers group and the
    computer accounts of the CA servers of the domain hold full control of their own objects. The
    certificate templates are covered by ANSSI-AD-002. It is skipped when a read fails, when
    Active Directory is not connected, and outside the forest root domain.

    .EXAMPLE
    Test-MtAnssiAdPkiAuthorityControl

    Returns $true when only the privileged set and the CA servers control these objects, $false
    otherwise, or $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPkiAuthorityControl
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-001',
        Title = 'Only privileged principals should control the certification authorities',
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

    Write-Verbose 'Starting Test-MtAnssiAdPkiAuthorityControl'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID was not found in the collected data.')
        return $null
    }

    if (-not (Get-MtAnssiAdDomainIsForestRoot -Domain $adState.Domain)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The PKI containers belong to the whole forest and their default permissions name ' +
            'the Domain Admins and the Cert Publishers of the forest root domain: run this test ' +
            'against the forest root domain.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $trusted = Get-MtAnssiAdTrustedSid -Privileged $privileged -Group $adState.Groups `
        -DomainSid $domainSid
    $assessment = Get-MtAnssiAdPkiContainerAssessment -AdState $adState -TrustedSid $trusted

    if ($assessment.ObjectCount -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No PKI container is visible to the account that reads the directory. The ' +
            'Public Key Services container exists in every forest, so the account may lack ' +
            'read access.')
        return $null
    }

    $findings = @($assessment.Finding)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            'No principal outside the privileged set holds a dangerous right on the ' +
            "$($assessment.ObjectCount) certificate containers and CA objects.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    Add-MtTestResultDetail -Result ("$($findings.Count) dangerous rights on the certificate " +
        "containers and CA objects are held by principals outside the privileged set.$note" +
        "`n`n$table")
    return $false
}
