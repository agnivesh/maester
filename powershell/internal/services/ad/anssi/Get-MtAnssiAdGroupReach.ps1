function Get-MtAnssiAdGroupReach {
    <#
    .SYNOPSIS
    Lists the accounts a group reaches through nested membership and primary groups.

    .DESCRIPTION
    Walks the member lists of a group and of every group nested in it, once each, so that a
    nesting loop ends. A member found in the index as a user or computer is returned with the
    link 'Member'. A user or computer whose primary group is one of the walked groups is returned
    with the link 'PrimaryGroup'. A member that is not in the index (for example a foreign
    security principal or an object of another domain) is returned as unresolved. Every walked
    group, the starting one included, is returned in Group.

    Throws when a walked group has no entry in the member map: a partial walk is never returned.

    .PARAMETER GroupDn
    The distinguished name of the group to start from.

    .PARAMETER MemberMap
    A hashtable from group distinguished name to the distinguished names of its direct members.

    .PARAMETER Index
    The index returned by Get-MtAnssiAdDirectoryIndex.

    .EXAMPLE
    Get-MtAnssiAdGroupReach -GroupDn $adminsDn -MemberMap $map -Index $index

    Returns an object with Account (one Entry and Link per path to a user or computer) and
    Unresolved (the member names that are not in the index).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string] $GroupDn,

        [Parameter(Mandatory)]
        [hashtable] $MemberMap,

        [Parameter(Mandatory)]
        [hashtable] $Index
    )

    $visited = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($GroupDn)
    $account = [System.Collections.Generic.List[object]]::new()
    $unresolved = [System.Collections.Generic.List[string]]::new()

    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        if (-not $visited.Add($current)) {
            continue
        }
        if (-not $MemberMap.ContainsKey($current)) {
            throw "The members of the group '$current' were not read: its nesting is unknown."
        }

        foreach ($memberDn in $MemberMap[$current]) {
            $entry = $Index.ByDn[[string]$memberDn]
            if ($null -eq $entry) {
                $unresolved.Add([string]$memberDn)
            } elseif ($entry.Kind -eq 'Group') {
                $pending.Push([string]$memberDn)
            } else {
                $account.Add([PSCustomObject]@{ Entry = $entry; Link = 'Member' })
            }
        }

        $groupSid = [string]$Index.ByDn[$current].Item.Sid.Value
        foreach ($entry in $Index.ByPrimaryGroup[$groupSid]) {
            $account.Add([PSCustomObject]@{ Entry = $entry; Link = 'PrimaryGroup' })
        }
    }

    return [PSCustomObject]@{
        Account    = $account.ToArray()
        Unresolved = $unresolved.ToArray()
        Group      = [string[]]@($visited)
    }
}
