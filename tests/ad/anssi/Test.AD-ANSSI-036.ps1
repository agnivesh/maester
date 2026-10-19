function Test-MtAnssiAdTrustForestSidHistory {
    <#
    .SYNOPSIS
    ANSSI-AD-036: Outbound forest trust relationships should not have SID history enabled.

    .DESCRIPTION
    Reports outbound forest trust relationships whose filtering has been relaxed so that the
    SID history mechanism is enabled.

    A trust relationship is reported when all of the following apply:
    - The trust is outbound or bidirectional: the local forest trusts the other forest.
    - The trust is a forest trust: FOREST_TRANSITIVE (0x8) is set.
    - TREAT_AS_EXTERNAL (0x40) is set: the forest trust is filtered like an external trust.

    Corresponds to the ANSSI Active Directory checkpoint vuln_trusts_forest_sidhistory.

    .EXAMPLE
    Test-MtAnssiAdTrustForestSidHistory

    Returns $true when no outbound forest trust has SID history enabled, $false when at least
    one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdTrustForestSidHistory
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-036',
        Title = 'Outbound forest trust relationships should not have SID history enabled',
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

    Write-Verbose 'Starting Test-MtAnssiAdTrustForestSidHistory'

    $directionOutbound = 0x2
    $forestTransitive = 0x8
    $treatAsExternal = 0x40
    $relaxedForestTrust = $forestTransitive -bor $treatAsExternal

    $adState = Get-MtADDomainState -Categories @('Trusts')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Trusts'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $trusts = @($adState.Trusts | Where-Object { $null -ne $_ })
    $relaxedTrusts = @($trusts | Where-Object {
            ($_.TrustDirection -band $directionOutbound) -ne 0 -and
            ($_.TrustAttributes -band $relaxedForestTrust) -eq $relaxedForestTrust
        })
    Write-Verbose "Trusts: $($trusts.Count), relaxed forest trusts: $($relaxedTrusts.Count)"

    if ($relaxedTrusts.Count -eq 0) {
        $summary = 'No outbound forest trust relationship with SID history enabled was found.'
        if ($trusts.Count -eq 0) {
            $summary = 'No trust relationship is configured in the domain.'
        }
        Add-MtTestResultDetail -Result $summary
        return $true
    }

    $directionNames = @{ 2 = 'Outbound'; 3 = 'Bidirectional' }
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $relaxedTrusts -Column ([ordered]@{
            'Trust partner' = { $_.TrustPartner }
            'Direction'     = { $directionNames[[int]$_.TrustDirection] }
            'Attributes'    = { '0x{0:X}' -f [int]$_.TrustAttributes }
        })

    $result = "Found $($relaxedTrusts.Count) outbound forest trust relationship(s) with SID " +
        "history enabled. An attacker having compromised a trusted forest can spoof users and " +
        "computers of the local forest.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
