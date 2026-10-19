function Test-MtAnssiAdDomainUpdateRevision {
    <#
    .SYNOPSIS
    ANSSI-AD-038: The domain preparation should not be at revision 15.

    .DESCRIPTION
    Revision 15 of the domain preparation (adprep /domainprep of Windows Server 2016) can give the
    Key Admins and Enterprise Key Admins groups far more rights than they need; revision 16 removes
    the excess. At revision 15 the test reads the domain root: it fails when one of the groups holds
    more than reading and writing msDS-KeyCredentialLink, and passes when only that narrow right is
    there (a corrected build or a manual fix leaves the revision at 15).

    The test is skipped when the domain was not collected, when the revision could not be read, or
    when the permissions of the domain root could not be read at revision 15.

    Corresponds to the ANSSI Active Directory checkpoint vuln_adupdate_bad.

    .EXAMPLE
    Test-MtAnssiAdDomainUpdateRevision

    Returns $true when the revision is not 15 or the Key Admins rights are narrow, $false when
    they are broad, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDomainUpdateRevision
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-038',
        Title = 'The domain preparation should not be at revision 15',
        Product = 'ad',
        Feature = 'domain-and-forest',
        Area = 'infrastructure',
        ResourceType = 'Tenant',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDomainUpdateRevision'

    $badRevision = 15

    $adState = Get-MtADDomainState -Categories @('Domain')

    $revision = $adState.Domain.DomainUpdateRevision
    if ($null -eq $revision) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The revision of the domain preparation was not found in the collected data.')
        return $null
    }

    Write-Verbose "Domain update revision: $revision"
    $domainName = Get-MtSafeMarkdown ([string]$adState.Domain.Name)

    if ($revision -ne $badRevision) {
        Add-MtTestResultDetail -Result (
            "The domain preparation of $domainName is at revision $revision.")
        return $true
    }

    $assessment = Get-MtAnssiAdKeyAdminsAssessment -AdState $adState

    if (-not $assessment.Readable) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The permissions of the domain root could not be read, so the test cannot tell ' +
            'whether the Key Admins groups hold more than they need at revision 15.')
        return $null
    }

    if ($assessment.Broad.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "The domain preparation of $domainName is at revision $badRevision, but the Key " +
            'Admins and Enterprise Key Admins groups hold only the narrow right on ' +
            'msDS-KeyCredentialLink on the domain root, so the excess that this revision ' +
            'normally causes is not present. Preparing the domain again to reach revision 16 ' +
            'is still advised.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $assessment.Broad `
        -DefaultDomain ([string]$adState.Domain.Name) -Column ([ordered]@{
            'Group'       = { $_.Group }
            'Sid'         = { $_.Sid }
            'Access mask' = { $_.Mask }
            'Object type' = { $_.ObjectType }
        })
    Add-MtTestResultDetail -Result (
        "The domain preparation of $domainName is at revision $badRevision and the Key Admins " +
        'groups hold more than they need on the domain root. Prepare the domain again with a ' +
        "Windows Server version 1709 or later medium to reach revision 16.`n`n$table")
    return $false
}
