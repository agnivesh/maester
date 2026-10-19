function Get-MtAnssiAdStrongComponent {
    <#
    .SYNOPSIS
    Lists the cycles of a directed graph as strongly connected components.

    .DESCRIPTION
    Second pass of Kosaraju's algorithm: walks the reversed graph from each node, in reverse
    finishing order, and collects the nodes each walk reaches. Every component of more than one
    node, or of one node that points to itself, holds a cycle and is returned.

    .PARAMETER Order
    The nodes in depth-first finishing order on the graph (Get-MtAnssiAdDepthFirstOrder).

    .PARAMETER Forward
    A hashtable from a node to the nodes it points to.

    .PARAMETER Reverse
    A hashtable from a node to the nodes that point to it.

    .EXAMPLE
    Get-MtAnssiAdStrongComponent -Order $order -Forward $forward -Reverse $reverse

    Returns one array of nodes per cycle.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Order,

        [Parameter(Mandatory)]
        [hashtable] $Forward,

        [Parameter(Mandatory)]
        [hashtable] $Reverse
    )

    $assigned = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $cycles = [System.Collections.Generic.List[object]]::new()
    for ($index = $Order.Count - 1; $index -ge 0; $index--) {
        $root = $Order[$index]
        if (-not $assigned.Add($root)) {
            continue
        }
        $component = [System.Collections.Generic.List[string]]::new()
        $pending = [System.Collections.Generic.Stack[string]]::new()
        $pending.Push($root)
        while ($pending.Count -gt 0) {
            $current = $pending.Pop()
            $component.Add($current)
            foreach ($source in $Reverse[$current]) {
                if ($assigned.Add([string]$source)) {
                    $pending.Push([string]$source)
                }
            }
        }
        if ($component.Count -gt 1 -or @($Forward[$root]) -contains $root) {
            $cycles.Add($component.ToArray())
        }
    }

    return $cycles.ToArray()
}
