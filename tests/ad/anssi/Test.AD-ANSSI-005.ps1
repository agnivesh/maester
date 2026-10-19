function Test-MtAnssiAdCriticalObjectAvailable {
    <#
    .SYNOPSIS
    ANSSI-AD-005: The critical directory objects should be readable.

    .DESCRIPTION
    Checks that the objects every privilege review depends on can be seen and their permissions
    read: AdminSDHolder, the built-in Administrator and krbtgt accounts, Domain Admins and, in the
    forest root domain, Schema Admins and Enterprise Admins. It fails when one is missing from the
    collected data or when its security descriptor cannot be read. This usually means that the
    permissions of these objects were changed so that the account running the scan cannot see
    them, which leaves the other checks blind; it is not a vulnerability by itself.

    The test is skipped when the domain SID or name is not in the collected data, or when a read
    fails, for example when AdminSDHolder cannot be read at all.

    .EXAMPLE
    Test-MtAnssiAdCriticalObjectAvailable

    Returns $true when every critical object is found and readable, $false otherwise, and $null
    when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdCriticalObjectAvailable
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-005',
        Title = 'The critical directory objects should be readable',
        Product = 'ad',
        Feature = 'directory-configuration',
        Area = 'infrastructure',
        ResourceType = 'Tenant',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdCriticalObjectAvailable'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Groups')

    if (-not $adState.Domain.DomainSID.Value -or -not $adState.Domain.DistinguishedName) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID or name was not found in the collected data.')
        return $null
    }

    $findings = @(Get-MtAnssiAdCriticalObject -AdState $adState)

    Write-Verbose "Critical objects with a problem: $($findings.Count)"
    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result 'Every critical object was found and its permissions read.'
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $findings -Column ([ordered]@{
            'Object'             = { $_.Object }
            'Distinguished name' = { $_.DistinguishedName }
            'Problem'            = { $_.Problem }
        })
    Add-MtTestResultDetail -Result ("$($findings.Count) critical objects are missing or cannot " +
        "be read, so the other checks may be incomplete.`n`n$table")
    return $false
}
