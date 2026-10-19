function Get-MtAnssiAdParentTrustSid {
    <#
    .SYNOPSIS
    Returns the SID of a forest's root domain from the trust that a child domain has for it.

    .DESCRIPTION
    Every child domain has a trust object for its parent, inside the forest (WITHIN_FOREST,
    0x20), with the parent's SID in securityIdentifier. Returns the SID of the first such trust
    whose partner is the given forest root domain, or $null when there is none, for example in a
    grandchild domain, whose parent is not the root. Names are compared without regard to case.

    .PARAMETER Trust
    The collected trust objects, with TrustPartner, TrustAttributes and Sid.

    .PARAMETER Forest
    The DNS name of the forest root domain.

    .EXAMPLE
    Get-MtAnssiAdParentTrustSid -Trust $adState.Trusts -Forest 'root.local'

    Returns the SID of root.local, or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Trust,

        [Parameter(Mandatory)]
        [string] $Forest
    )

    foreach ($item in $Trust) {
        $inForest = (($item.TrustAttributes -as [int]) -band 0x20) -ne 0
        $sid = [string]$item.Sid.Value
        if ($inForest -and $sid -and [string]$item.TrustPartner -eq $Forest) { return $sid }
    }
    return $null
}
