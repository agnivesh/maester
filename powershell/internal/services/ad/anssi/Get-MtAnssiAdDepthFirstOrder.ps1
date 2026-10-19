function Get-MtAnssiAdDepthFirstOrder {
    <#
    .SYNOPSIS
    Lists the nodes of a directed graph in depth-first finishing order.

    .DESCRIPTION
    Walks the graph depth first from each node not yet visited, without recursion, so that a
    deep chain does not exhaust the call stack, and returns every node in the order its walk
    finished. Used as the first pass of Kosaraju's strongly connected components algorithm.

    .PARAMETER Node
    The nodes of the graph.

    .PARAMETER Edge
    A hashtable from a node to the nodes it points to.

    .EXAMPLE
    Get-MtAnssiAdDepthFirstOrder -Node $dn -Edge $forward

    Returns the nodes in finishing order.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Node,

        [Parameter(Mandatory)]
        [hashtable] $Edge
    )

    $visited = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $order = [System.Collections.Generic.List[string]]::new()
    foreach ($start in $Node) {
        if (-not $visited.Add($start)) {
            continue
        }
        $stack = [System.Collections.Generic.Stack[object]]::new()
        $stack.Push(@($start, 0, @(foreach ($target in $Edge[$start]) { $target })))
        while ($stack.Count -gt 0) {
            $frame = $stack.Peek()
            if ($frame[1] -lt $frame[2].Count) {
                $child = [string]$frame[2][$frame[1]]
                $frame[1]++
                if ($visited.Add($child)) {
                    $stack.Push(@($child, 0, @(foreach ($target in $Edge[$child]) { $target })))
                }
            } else {
                $null = $stack.Pop()
                $order.Add($frame[0])
            }
        }
    }

    return $order.ToArray()
}
