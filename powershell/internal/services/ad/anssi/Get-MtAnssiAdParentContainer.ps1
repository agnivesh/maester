function Get-MtAnssiAdParentContainer {
    <#
    .SYNOPSIS
    Lists the containers above directory objects, up to the domain root.

    .DESCRIPTION
    Returns, once each and in the order first met, the distinguished names of the containers and
    organizational units above each object, the nearest first, stopping below the domain root.
    The domain root itself and anything outside the domain are left out. Commas escaped with a
    backslash inside a name are kept.

    .PARAMETER DistinguishedName
    The objects.

    .PARAMETER DomainDn
    The distinguished name of the domain root.

    .EXAMPLE
    Get-MtAnssiAdParentContainer -DistinguishedName 'CN=a,OU=b,OU=c,DC=x' -DomainDn 'DC=x'

    Returns OU=b,OU=c,DC=x and OU=c,DC=x.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $DistinguishedName,

        [Parameter(Mandatory)]
        [string] $DomainDn
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $suffix = ",$DomainDn"
    foreach ($name in $DistinguishedName) {
        $parts = [regex]::Split($name, '(?<!\\),')
        for ($index = 1; $index -lt $parts.Count; $index++) {
            $parent = $parts[$index..($parts.Count - 1)] -join ','
            if (-not $parent.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                break
            }
            if ($seen.Add($parent)) {
                $parent
            }
        }
    }
}
