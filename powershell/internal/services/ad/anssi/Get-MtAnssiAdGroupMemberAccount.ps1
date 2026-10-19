function Get-MtAnssiAdGroupMemberAccount {
    <#
    .SYNOPSIS
    Lists the users and computers that are members of a group, directly or through nesting.

    .DESCRIPTION
    Finds the group with the given SID in the collected groups, reads its members and the members
    of every group nested in it (through the session member map, so reads are shared with the
    other ANSSI tests), and adds the accounts whose primary group it is.

    Returns an object with Group (the collected group, or $null when it is not in the collected
    data), MemberDn (a case-insensitive set of the member accounts' distinguished names),
    NestedGroup (the distinguished names of the groups nested in it, at any depth) and Unresolved
    (the distinguished names of members outside the collected data). Throws when a member list
    cannot be read.

    .PARAMETER AdState
    The collected state, with the Domain, Users, Computers and Groups categories.

    .PARAMETER GroupSid
    The SID of the group, for example the domain SID followed by -525 for Protected Users.

    .EXAMPLE
    Get-MtAnssiAdGroupMemberAccount -AdState $adState -GroupSid "$domainSid-525"

    Returns the members of Protected Users.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [object] $AdState,

        [Parameter(Mandatory)]
        [string] $GroupSid
    )

    $index = Get-MtAnssiAdDirectoryIndex -User $AdState.Users -Computer $AdState.Computers `
        -Group $AdState.Groups -DomainSid ([string]$AdState.Domain.DomainSID.Value)
    $memberDn = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $group = $index.BySid[$GroupSid]
    if ($null -eq $group) {
        return [PSCustomObject]@{
            Group = $null; MemberDn = $memberDn; NestedGroup = @(); Unresolved = @()
        }
    }

    $groupDn = [string]$group.Item.DistinguishedName
    $memberMap = Get-MtAnssiAdMemberMapCache -ProtocolEvidence $AdState.ProtocolEvidence
    Read-MtAnssiAdGroupMemberMap -GroupDn @($groupDn) -Index $index -MemberMap $memberMap `
        -ProtocolEvidence $AdState.ProtocolEvidence
    $reach = Get-MtAnssiAdGroupReach -GroupDn $groupDn -MemberMap $memberMap -Index $index
    foreach ($hit in $reach.Account) {
        $null = $memberDn.Add([string]$hit.Entry.Item.DistinguishedName)
    }

    Write-Verbose "Group $GroupSid has $($memberDn.Count) member account(s)."
    return [PSCustomObject]@{
        Group       = $group.Item
        MemberDn    = $memberDn
        NestedGroup = @($reach.Group | Where-Object { $_ -ne $groupDn })
        Unresolved  = @($reach.Unresolved)
    }
}
