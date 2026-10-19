function Get-MtAnssiAdSidByDn {
    <#
    .SYNOPSIS
    Builds a lookup from distinguished name to SID and name for the collected objects.

    .DESCRIPTION
    Goes once through the collected users, computers and groups and returns a hashtable keyed
    by distinguished name. Each value holds the Sid (as text) and the Name of the object.
    Hashtable keys ignore case, like distinguished names. Objects without a SID are left out.

    .PARAMETER User
    The user accounts, as collected for the Users category.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .PARAMETER Group
    The groups, as collected for the Groups category.

    .EXAMPLE
    $lookup = Get-MtAnssiAdSidByDn -User $users -Computer $computers -Group $groups

    Returns the lookup to pass to Resolve-MtAnssiAdSid.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()]
        [object[]] $User,

        [AllowNull()]
        [object[]] $Computer,

        [AllowNull()]
        [object[]] $Group
    )

    $lookup = @{}
    foreach ($list in @(, $User) + @(, $Computer) + @(, $Group)) {
        foreach ($item in $list) {
            $sid = [string]$item.Sid.Value
            if ($sid -and $item.DistinguishedName) {
                $entry = @{ Sid = $sid; Name = [string]$item.Name }
                $lookup[[string]$item.DistinguishedName] = $entry
            }
        }
    }

    return $lookup
}
