function Test-MtAnssiAdPkiTemplatePermission {
    <#
    .SYNOPSIS
    ANSSI-AD-002: Only privileged principals should be able to change certificate templates.

    .DESCRIPTION
    Reads the owner and permissions of every certificate template of the forest and fails when a
    principal outside the privileged set can change one: full control, writing the permissions,
    the owner or any attribute, or owning it. A right on a template that a CA publishes is level
    1 (Critical) when it is level 1 in the control table; any other finding is level 2 (High).
    The most severe level found is reported. Enrollment rights are not judged.

    Templates are forest-wide and their default permissions name the Domain Admins of the forest
    root domain, so the test is skipped outside the forest root domain, and when a read fails or
    the permissions of a template could not be read.

    .EXAMPLE
    Test-MtAnssiAdPkiTemplatePermission

    Returns $true when no principal outside the privileged set can change a template, $false
    when one can, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPkiTemplatePermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-002',
        Title = 'Only privileged principals should be able to change certificate templates',
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

    Write-Verbose 'Starting Test-MtAnssiAdPkiTemplatePermission'

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
    $head = @(Get-MtAnssiAdNamingContextHead -ProtocolEvidence $adState.ProtocolEvidence)
    $services = @($head -like 'CN=Configuration,*' | ForEach-Object { "CN=Services,$_" })
    $templates = @(Get-MtAnssiAdSearchSecurity -SearchBase $services -Scope Subtree `
            -Filter '(objectClass=pKICertificateTemplate)' `
            -ProtocolEvidence $adState.ProtocolEvidence)
    $enrollment = @(Get-MtAnssiAdSearchSecurity -SearchBase $services -Scope Subtree `
            -Filter '(objectClass=pKIEnrollmentService)' -Attribute @('certificateTemplates') `
            -ProtocolEvidence $adState.ProtocolEvidence)
    $rows = @(Get-MtAnssiAdAceControl -Object $templates -TrustedSid $trusted)

    $findings = @(Get-MtAnssiAdTemplateFinding -Row $rows -EnrollmentService $enrollment)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2) -Result (
            'No principal outside the privileged set can change the ' +
            "$($templates.Count) certificate templates.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) rights to change certificate templates are held by " +
        "principals outside the privileged set.$note`n`n$table"
    Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade @($findings.Level)) `
        -Result $result
    return $false
}
