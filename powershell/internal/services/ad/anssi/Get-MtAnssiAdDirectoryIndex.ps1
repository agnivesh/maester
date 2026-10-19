function Get-MtAnssiAdDirectoryIndex {
    <#
    .SYNOPSIS
    Indexes the collected users, computers and groups for the privileged-account helpers.

    .DESCRIPTION
    Goes once through the collected objects and returns three hashtables:

    - ByDn: distinguished name to entry;
    - BySid: SID (as text) to entry;
    - ByPrimaryGroup: SID of a domain group to the user and computer entries whose primary group
      it is (built from PrimaryGroupId and the domain SID).

    Each entry holds the Kind (User, Computer or Group) and the collected Item. Hashtable keys
    ignore case, like distinguished names.

    .PARAMETER User
    The user accounts, as collected for the Users category.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .PARAMETER Group
    The groups, as collected for the Groups category.

    .PARAMETER DomainSid
    The SID of the collected domain, used to turn a primary group RID into a group SID.

    .EXAMPLE
    $index = Get-MtAnssiAdDirectoryIndex -User $users -Computer $computers -Group $groups `
        -DomainSid $domainSid

    Returns the index used by Get-MtAnssiAdGroupReach and Resolve-MtAnssiAdPrivilegedClosure.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()]
        [object[]] $User,

        [AllowNull()]
        [object[]] $Computer,

        [AllowNull()]
        [object[]] $Group,

        [Parameter(Mandatory)]
        [string] $DomainSid
    )

    $byDn = @{}
    $bySid = @{}
    $byPrimaryGroup = @{}
    $sets = @(
        @{ Kind = 'User'; List = $User }
        @{ Kind = 'Computer'; List = $Computer }
        @{ Kind = 'Group'; List = $Group }
    )

    foreach ($set in $sets) {
        foreach ($item in $set.List) {
            $entry = @{ Kind = $set.Kind; Item = $item }
            $byDn[[string]$item.DistinguishedName] = $entry
            $bySid[[string]$item.Sid.Value] = $entry
            if ($null -eq $item.PrimaryGroupId) {
                continue
            }
            $groupSid = "$DomainSid-$([string]$item.PrimaryGroupId)"
            if (-not $byPrimaryGroup.ContainsKey($groupSid)) {
                $byPrimaryGroup[$groupSid] = [System.Collections.Generic.List[object]]::new()
            }
            $byPrimaryGroup[$groupSid].Add($entry)
        }
    }

    return @{
        ByDn           = $byDn
        BySid          = $bySid
        ByPrimaryGroup = $byPrimaryGroup
    }
}
