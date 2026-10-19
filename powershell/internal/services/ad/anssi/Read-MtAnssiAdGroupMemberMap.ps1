function Read-MtAnssiAdGroupMemberMap {
    <#
    .SYNOPSIS
    Reads the direct members of some groups and of every group nested in them.

    .DESCRIPTION
    Starts from the given groups and reads the member attribute of each group not yet in the
    member map, over one LDAP connection. Members found in the index as groups are read in turn,
    once each, so that a nesting loop ends. Every member list read is stored in MemberMap (group
    distinguished name to member distinguished names), which the caller can keep between calls:
    groups already in the map are not read again.

    Throws when a read fails. A group is only added to the map once its whole member list was
    read, so a map left by a failed call holds complete entries only.

    .PARAMETER GroupDn
    The distinguished names of the groups to start from.

    .PARAMETER Index
    The index returned by Get-MtAnssiAdDirectoryIndex, used to recognize nested groups.

    .PARAMETER MemberMap
    The hashtable to fill. It is changed in place.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Read-MtAnssiAdGroupMemberMap -GroupDn $rootDn -Index $index -MemberMap $map `
        -ProtocolEvidence $adState.ProtocolEvidence

    Fills $map with the member lists of the groups and of the groups nested in them.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $GroupDn,

        [Parameter(Mandatory)]
        [hashtable] $Index,

        [Parameter(Mandatory)]
        [hashtable] $MemberMap,

        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new([string[]]$GroupDn)
    $connection = $null
    try {
        while ($pending.Count -gt 0) {
            $current = $pending.Pop()
            if (-not $visited.Add($current)) {
                continue
            }
            if (-not $MemberMap.ContainsKey($current)) {
                if ($null -eq $connection) {
                    $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
                }
                $MemberMap[$current] = [string[]]@(Get-MtLdapRangedValue -Connection $connection `
                        -DistinguishedName $current -AttributeName 'member')
            }
            foreach ($memberDn in $MemberMap[$current]) {
                if ($Index.ByDn[$memberDn].Kind -eq 'Group') {
                    $pending.Push($memberDn)
                }
            }
        }
    } finally {
        if ($null -ne $connection) {
            $connection.Dispose()
        }
    }

    Write-Verbose "Member lists known for $($MemberMap.Count) group(s)."
}
