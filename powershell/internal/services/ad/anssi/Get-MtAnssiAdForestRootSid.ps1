function Get-MtAnssiAdForestRootSid {
    <#
    .SYNOPSIS
    Returns the SID of the forest root domain from the collected state.

    .DESCRIPTION
    A domain controller holds the naming context of its own domain only, so a test that runs from a
    child domain cannot read the forest root domain object. When the domain is the forest root, its
    own SID is returned. Otherwise the SID is taken from the trust object that every child domain
    has for its parent: a trust inside the forest (WITHIN_FOREST, 0x20) whose partner is the forest
    root, whose securityIdentifier is the SID of that domain. Throws when no such trust exists, for
    example in a grandchild domain, because then the SID is unknown and a caller must skip instead
    of judging with a partial trusted set. Domain names are compared without regard to case.

    .PARAMETER Domain
    The collected Domain object, with DnsRoot, Forest and DomainSID.

    .PARAMETER Trust
    The collected trust objects, with TrustPartner, TrustAttributes and Sid.

    .EXAMPLE
    Get-MtAnssiAdForestRootSid -Domain $adState.Domain -Trust $adState.Trusts

    Returns the SID of the forest root domain, for example S-1-5-21-1-2-3.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object] $Domain,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Trust
    )

    $forest = [string]$Domain.Forest
    $dnsRoot = [string]$Domain.DnsRoot
    if (-not $forest -or -not $dnsRoot) {
        throw 'The forest root domain is unknown: the collected domain has no DNS name or forest.'
    }

    if ($dnsRoot -eq $forest) {
        $own = [string]$Domain.DomainSID.Value
        if (-not $own) { throw "The SID of the forest root domain '$forest' was not collected." }
        return $own
    }

    $parent = Get-MtAnssiAdParentTrustSid -Trust $Trust -Forest $forest
    if (-not $parent) {
        throw "The SID of the forest root domain '$forest' was not found among the trusts of " +
        "'$dnsRoot': run the test against the forest root domain."
    }
    return $parent
}
