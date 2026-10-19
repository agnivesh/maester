function Get-MtAnssiAdAppliedGpo {
    <#
    .SYNOPSIS
    Lists the group policy objects that apply to directory objects through their containers.

    .DESCRIPTION
    For each object, builds the chain of its containers up to the domain root and keeps the GPOs
    that Select-MtAnssiAdLinkedGpo finds on it; objects in the same container share one chain,
    which is worked out once. Returns one row per GPO with its distinguished name and the number
    of objects it applies to, the GPO most often applied first. Throws when a container of a
    chain is missing from the containers given, so that a partial read is never reported as
    fewer GPOs.

    .PARAMETER DistinguishedName
    The objects, for example the privileged accounts.

    .PARAMETER Container
    The containers read with Get-MtLdapObjectSecurity and the gPLink and gPOptions attributes,
    the domain root included.

    .PARAMETER DomainDn
    The distinguished name of the domain root.

    .EXAMPLE
    Get-MtAnssiAdAppliedGpo -DistinguishedName $accounts -Container $containers -DomainDn $domainDn

    Returns rows with DistinguishedName and Count.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $DistinguishedName,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Container,

        [Parameter(Mandatory)]
        [string] $DomainDn
    )

    $byDn = @{}
    foreach ($item in $Container) { $byDn[[string]$item.DistinguishedName] = $item }
    $byParent = @{}
    foreach ($name in $DistinguishedName) {
        $parent = [string][regex]::Split($name, '(?<!\\),', 2)[1]
        if (-not $byParent.ContainsKey($parent)) {
            $byParent[$parent] = @{ Sample = $name; Count = 0 }
        }
        $byParent[$parent].Count++
    }

    $count = @{}
    foreach ($group in $byParent.Values) {
        $chainDn = @(Get-MtAnssiAdParentContainer -DistinguishedName @($group.Sample) `
                -DomainDn $DomainDn) + @($DomainDn)
        $missing = @($chainDn | Where-Object { -not $byDn.ContainsKey($_) })
        if ($missing.Count -gt 0) {
            throw "The container '$($missing[0])' was not read: the GPOs that apply are unknown."
        }
        $gpo = @(Select-MtAnssiAdLinkedGpo -Chain @($chainDn | ForEach-Object { $byDn[$_] }))
        foreach ($dn in @($gpo | Sort-Object -Unique)) {
            $count[$dn] = $group.Count + [int]$count[$dn]
        }
    }

    $rows = foreach ($key in $count.Keys) {
        [PSCustomObject]@{ DistinguishedName = $key; Count = $count[$key] }
    }
    return @($rows | Sort-Object -Property @{ Expression = 'Count'; Descending = $true },
        DistinguishedName)
}
