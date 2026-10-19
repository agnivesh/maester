function Get-MtAnssiAdDomainIsForestRoot {
    <#
    .SYNOPSIS
    Returns whether the collected domain is the root domain of its forest.

    .DESCRIPTION
    The PKI containers and certificate templates belong to the whole forest, and their default
    permissions name groups of the forest root domain. A test about them is only meaningful when it
    runs against that domain. An unknown DNS root or forest counts as not the root, so the test
    skips instead of guessing.

    .PARAMETER Domain
    The domain object of the AD state, with DnsRoot and Forest.

    .EXAMPLE
    Get-MtAnssiAdDomainIsForestRoot -Domain $adState.Domain

    Returns $true when DnsRoot and Forest name the same domain.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object] $Domain
    )

    $dnsRoot = [string]$Domain.DnsRoot
    return [bool]($dnsRoot -and $dnsRoot -eq [string]$Domain.Forest)
}
