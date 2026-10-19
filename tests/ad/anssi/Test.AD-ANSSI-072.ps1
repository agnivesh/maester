function Test-MtAnssiAdTrustTgtDelegation {
    <#
    .SYNOPSIS
    ANSSI-AD-072: Inbound trust relationships should not allow Kerberos delegation.

    .DESCRIPTION
    Reports inbound trust relationships that explicitly allow Kerberos TGT delegation.

    A trust relationship is reported when all of the following apply:
    - The trust is inbound or bidirectional: another domain or forest trusts the local domain.
    - CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x800) is set: delegation is explicitly allowed.

    Corresponds to the ANSSI Active Directory checkpoint vuln_trusts_tgt_deleg.

    .EXAMPLE
    Test-MtAnssiAdTrustTgtDelegation

    Returns $true when no inbound trust allows Kerberos delegation, $false when at least one
    does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdTrustTgtDelegation
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-072',
        Title = 'Inbound trust relationships should not allow Kerberos delegation',
        Product = 'ad',
        Feature = 'trusts',
        Area = 'access-control',
        ResourceType = 'Trust',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1558',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdTrustTgtDelegation'

    $directionInbound = 0x1
    $enableTgtDelegation = 0x800

    $adState = Get-MtADDomainState -Categories @('Trusts')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Trusts'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $trusts = @($adState.Trusts | Where-Object { $null -ne $_ })
    $delegatingTrusts = @($trusts | Where-Object {
            ($_.TrustDirection -band $directionInbound) -ne 0 -and
            ($_.TrustAttributes -band $enableTgtDelegation) -ne 0
        })
    Write-Verbose "Trusts: $($trusts.Count), allowing TGT delegation: $($delegatingTrusts.Count)"

    if ($delegatingTrusts.Count -eq 0) {
        $summary = 'No inbound trust relationship allowing Kerberos delegation was found.'
        if ($trusts.Count -eq 0) {
            $summary = 'No trust relationship is configured in the domain.'
        }
        Add-MtTestResultDetail -Result $summary
        return $true
    }

    $directionNames = @{ 1 = 'Inbound'; 3 = 'Bidirectional' }
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $delegatingTrusts -Column ([ordered]@{
            'Trust partner' = { $_.TrustPartner }
            'Direction'     = { $directionNames[[int]$_.TrustDirection] }
            'Attributes'    = { '0x{0:X}' -f [int]$_.TrustAttributes }
        })

    $result = "Found $($delegatingTrusts.Count) inbound trust relationship(s) that allow " +
        "Kerberos delegation. A compromised resource of a trusting domain can authenticate " +
        "as the accounts of the local domain that use it.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
