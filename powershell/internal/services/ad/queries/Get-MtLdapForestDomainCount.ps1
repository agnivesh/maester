function Get-MtLdapForestDomainCount {
    <#
    .SYNOPSIS
    Counts the domains of the forest from the crossRef objects of the Partitions container.

    .DESCRIPTION
    A crossRef object stands for a domain when its systemFlags has both bit 0x1 (the naming
    context is in the directory) and bit 0x2 (the naming context is a domain); the
    Configuration, Schema and application partitions have only 0x1. Returns the number of
    domains, or $null when none is recognized, which means the flags could not be read.

    .PARAMETER CrossRef
    The crossRef objects, with their systemFlags.

    .EXAMPLE
    Get-MtLdapForestDomainCount -CrossRef $crossRefs

    Returns the number of domains in the forest.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [AllowNull()]
        [object[]] $CrossRef
    )

    $domains = @($CrossRef | Where-Object { (($_.systemFlags -as [int]) -band 3) -eq 3 })
    if ($domains.Count -eq 0) {
        return $null
    }
    return $domains.Count
}
