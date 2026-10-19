function Select-MtAnssiAdLinkedGpo {
    <#
    .SYNOPSIS
    Returns the group policy objects linked to a chain of containers that apply below it.

    .DESCRIPTION
    Goes up the chain from the container nearest to an object to the domain root. Every enabled
    link applies until a container on the way blocks inheritance (gPOptions bit 0x1); above it,
    only enforced links still apply (Microsoft Learn, Group Policy processing). Disabled links
    never apply. Returns the distinguished names of the GPOs. Security filtering, WMI filters and
    site links are not taken into account.

    .PARAMETER Chain
    The containers, nearest first, each with a DistinguishedName and an Attribute dictionary
    holding gPLink and gPOptions (as returned by Get-MtLdapObjectSecurity).

    .EXAMPLE
    Select-MtAnssiAdLinkedGpo -Chain $containers

    Returns the GPOs that apply to an object placed in the first container.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Chain
    )

    $blocked = $false
    foreach ($container in $Chain) {
        foreach ($link in @(ConvertFrom-MtAnssiAdGpLink -Value $container.Attribute['gPLink'])) {
            if (-not $link.Disabled -and ($link.Enforced -or -not $blocked)) {
                $link.Gpo
            }
        }
        if ([int]$container.Attribute['gPOptions'] -band 1) {
            $blocked = $true
        }
    }
}
