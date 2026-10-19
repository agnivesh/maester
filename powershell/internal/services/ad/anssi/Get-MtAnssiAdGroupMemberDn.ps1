function Get-MtAnssiAdGroupMemberDn {
    <#
    .SYNOPSIS
    Reads the direct members of a group identified by its SID.

    .DESCRIPTION
    Finds the group with the given SID in the collected groups and reads the distinguished names
    of its direct members over LDAP.

    Returns $null when the group is not in the collected data. Returns an object with the group
    and its member names otherwise; the member list is empty for an empty group. Throws when the
    members cannot be read, so that a failed read is never mistaken for an empty group.

    .PARAMETER Group
    The groups, as collected for the Groups category.

    .PARAMETER Sid
    The SID of the group, for example S-1-5-32-554 or a domain SID followed by -571.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdGroupMemberDn -Group $adState.Groups -Sid 'S-1-5-32-554' `
        -ProtocolEvidence $adState.ProtocolEvidence

    Returns the group and the distinguished names of its direct members.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [AllowNull()]
        [object[]] $Group,

        [Parameter(Mandatory)]
        [string] $Sid,

        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $found = $Group | Where-Object { $_.Sid.Value -eq $Sid } | Select-Object -First 1

    if ($null -eq $found) {
        return $null
    }

    $connection = $null
    try {
        $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
        $memberDn = @(Get-MtLdapRangedValue -Connection $connection `
                -DistinguishedName $found.DistinguishedName -AttributeName 'member')
    } finally {
        if ($null -ne $connection) {
            $connection.Dispose()
        }
    }

    Write-Verbose "Group $Sid has $($memberDn.Count) direct member(s)."
    return [PSCustomObject]@{
        Group  = $found
        Member = $memberDn
    }
}
