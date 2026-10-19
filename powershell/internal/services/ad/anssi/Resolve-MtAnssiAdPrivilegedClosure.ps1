function Resolve-MtAnssiAdPrivilegedClosure {
    <#
    .SYNOPSIS
    Lists the privileged accounts of the domain from its protected groups and member lists.

    .DESCRIPTION
    Walks each protected group with Get-MtAnssiAdGroupReach and adds the built-in Administrator
    (RID 500) and krbtgt (RID 502) accounts, which are protected on their own. Each account is
    returned once, with every protected group it reaches and every way it reaches them (Link:
    Member, PrimaryGroup or ProtectedAccount). Members that are not in the collected data are
    returned once each in Unresolved, with the protected groups they were found under. Group
    lists the distinguished names of every walked group, roots and nested groups, sorted. Throws
    when a walked group has no entry in the member map.

    .PARAMETER RootGroup
    The protected groups found in the collected data.

    .PARAMETER MemberMap
    A hashtable from group distinguished name to the distinguished names of its direct members.
    It must hold every group nested in the protected groups.

    .PARAMETER Index
    The index returned by Get-MtAnssiAdDirectoryIndex.

    .PARAMETER DomainSid
    The SID of the collected domain.

    .EXAMPLE
    Resolve-MtAnssiAdPrivilegedClosure -RootGroup $roots -MemberMap $map -Index $index `
        -DomainSid $domainSid

    Returns an object with the Account and Unresolved lists.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $RootGroup,

        [Parameter(Mandatory)]
        [hashtable] $MemberMap,

        [Parameter(Mandatory)]
        [hashtable] $Index,

        [Parameter(Mandatory)]
        [string] $DomainSid
    )

    $hits = [System.Collections.Generic.List[object]]::new()
    $missing = [System.Collections.Generic.List[object]]::new()
    $groupDn = [System.Collections.Generic.SortedSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($root in $RootGroup) {
        $groupName = [string]$root.Name
        $reach = Get-MtAnssiAdGroupReach -GroupDn $root.DistinguishedName -MemberMap $MemberMap `
            -Index $Index
        foreach ($hit in $reach.Account) {
            $hits.Add([PSCustomObject]@{ Entry = $hit.Entry; Group = $groupName; Link = $hit.Link })
        }
        $groupDn.UnionWith([string[]]$reach.Group)
        foreach ($dn in $reach.Unresolved) {
            $missing.Add([PSCustomObject]@{ DistinguishedName = $dn; Group = $groupName })
        }
    }

    foreach ($rid in 500, 502) {
        $entry = $Index.BySid["$DomainSid-$rid"]
        if ($null -ne $entry) {
            $label = "Protected account (RID $rid)"
            $link = 'ProtectedAccount'
            $hits.Add([PSCustomObject]@{ Entry = $entry; Group = $label; Link = $link })
        }
    }

    $account = ConvertTo-MtAnssiAdPrivilegedAccount -Hit $hits.ToArray()

    $unresolved = foreach ($bucket in @($missing | Group-Object -Property DistinguishedName)) {
        [PSCustomObject]@{
            DistinguishedName = $bucket.Name
            Group             = @($bucket.Group.Group | Sort-Object -Unique)
        }
    }

    return [PSCustomObject]@{
        Account    = @($account)
        Unresolved = @($unresolved)
        Group      = [string[]]@($groupDn)
    }
}
