function Test-MtAnssiAdTrustDomainNotFiltered {
    <#
    .SYNOPSIS
    ANSSI-AD-035: Outbound domain trust relationships should be filtered (quarantined).

    .DESCRIPTION
    Reports outbound trust relationships to domains outside of the forest that are not
    quarantined, that is without SID filtering.

    A trust relationship is reported when all of the following apply:
    - The trust is outbound or bidirectional: the local domain trusts the other domain.
    - The trust is to a Windows domain (downlevel or uplevel). MIT and DCE realm trusts carry
      no SIDs.
    - QUARANTINED_DOMAIN (0x4) is not set.
    - WITHIN_FOREST (0x20) is not set.
    - FOREST_TRANSITIVE (0x8) is not set. Forest trusts are filtered by default and are not
      evaluated by this test.

    Corresponds to the ANSSI Active Directory checkpoint vuln_trusts_domain_notfiltered.

    .EXAMPLE
    Test-MtAnssiAdTrustDomainNotFiltered

    Returns $true when no unfiltered outbound domain trust relationship exists, $false when at
    least one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdTrustDomainNotFiltered
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-035',
        Title = 'Outbound domain trust relationships should be filtered (quarantined)',
        Product = 'ad',
        Feature = 'trusts',
        Area = 'access-control',
        ResourceType = 'Trust',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1134.005',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdTrustDomainNotFiltered'

    $directionOutbound = 0x2
    $typeDownlevel = 1
    $typeUplevel = 2
    $quarantinedDomain = 0x4
    $forestTransitive = 0x8
    $withinForest = 0x20
    $filteredOrOutOfScope = $quarantinedDomain -bor $forestTransitive -bor $withinForest

    $adState = Get-MtADDomainState -Categories @('Trusts')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Trusts'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $trusts = @($adState.Trusts | Where-Object { $null -ne $_ })
    $unfilteredTrusts = @($trusts | Where-Object {
            ($_.TrustDirection -band $directionOutbound) -ne 0 -and
            ($_.TrustType -in $typeDownlevel, $typeUplevel) -and
            ($_.TrustAttributes -band $filteredOrOutOfScope) -eq 0
        })
    Write-Verbose "Trusts: $($trusts.Count), unfiltered outbound: $($unfilteredTrusts.Count)"

    if ($unfilteredTrusts.Count -eq 0) {
        $summary = 'No unfiltered outbound domain trust relationship was found.'
        if ($trusts.Count -eq 0) {
            $summary = 'No trust relationship is configured in the domain.'
        }
        Add-MtTestResultDetail -Result $summary
        return $true
    }

    $directionNames = @{ 2 = 'Outbound'; 3 = 'Bidirectional' }
    $typeNames = @{ 1 = 'Downlevel (Windows NT)'; 2 = 'Uplevel (Active Directory)' }
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $unfilteredTrusts -Column ([ordered]@{
            'Trust partner' = { $_.TrustPartner }
            'Direction'     = { $directionNames[[int]$_.TrustDirection] }
            'Type'          = { $typeNames[[int]$_.TrustType] }
            'Attributes'    = { '0x{0:X}' -f [int]$_.TrustAttributes }
        })

    $result = "Found $($unfilteredTrusts.Count) outbound domain trust relationship(s) without " +
        "quarantine. An attacker having compromised a trusted domain can spoof users and " +
        "computers of the local domain.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
