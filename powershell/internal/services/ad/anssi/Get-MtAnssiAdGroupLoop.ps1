function Get-MtAnssiAdGroupLoop {
    <#
    .SYNOPSIS
    Finds the loops in group nesting among the collected groups.

    .DESCRIPTION
    Builds the nesting graph from each group's MemberOf (its parent groups) and returns its
    cycles: sets of groups that are, through
    nesting, members of each other. Each loop is returned once, as its groups sorted by name; the
    loops are sorted by the name of their first group.

    .PARAMETER Group
    The groups, as collected for the Groups category, with MemberOf.

    .EXAMPLE
    Get-MtAnssiAdGroupLoop -Group $adState.Groups

    Returns one object per loop, with Group (the groups in it).
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Group
    )

    $byDn = @{}
    foreach ($item in $Group) {
        $byDn[[string]$item.DistinguishedName] = $item
    }
    $forward = @{}
    $reverse = @{}
    foreach ($item in $Group) {
        $child = [string]$item.DistinguishedName
        $forward[$child] = @($item.MemberOf)
        foreach ($parent in $forward[$child]) {
            if (-not $reverse.ContainsKey([string]$parent)) {
                $reverse[[string]$parent] = [System.Collections.Generic.List[string]]::new()
            }
            $reverse[[string]$parent].Add($child)
        }
    }

    $order = @(Get-MtAnssiAdDepthFirstOrder -Node @($forward.Keys) -Edge $forward)
    $cycles = @(Get-MtAnssiAdStrongComponent -Order $order -Forward $forward -Reverse $reverse)
    $loops = foreach ($cycle in $cycles) {
        $members = @($cycle | ForEach-Object { $byDn[$_] } | Sort-Object -Property Name)
        [PSCustomObject]@{ Group = $members }
    }
    return @($loops | Sort-Object -Property { $_.Group[0].Name })
}
