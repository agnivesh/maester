function ConvertTo-MtAnssiAdPrivilegedAccount {
    <#
    .SYNOPSIS
    Merges the paths that make accounts privileged into one entry per account.

    .DESCRIPTION
    Takes one hit per path from a protected group (or a protected account) to a user or computer
    and returns one object per account, with the sorted, distinct names of the protected groups
    it reaches and the sorted, distinct ways it reaches them. Accounts are matched by
    distinguished name. Works in linear time, so that a domain where every user is privileged
    (for example Domain Users nested in Administrators) is still processed quickly.

    .PARAMETER Hit
    The paths, each with Entry (an entry of Get-MtAnssiAdDirectoryIndex), Group (the name of
    the protected group or account) and Link (Member, PrimaryGroup or ProtectedAccount).

    .EXAMPLE
    ConvertTo-MtAnssiAdPrivilegedAccount -Hit $hits

    Returns one object per account with DistinguishedName, Kind, Item, Group and Link.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Hit
    )

    $merged = @{}
    foreach ($path in $Hit) {
        $dn = [string]$path.Entry.Item.DistinguishedName
        $account = $merged[$dn]
        if ($null -eq $account) {
            $account = @{
                Entry = $path.Entry
                Group = [System.Collections.Generic.SortedSet[string]]::new()
                Link  = [System.Collections.Generic.SortedSet[string]]::new()
            }
            $merged[$dn] = $account
        }
        $null = $account.Group.Add($path.Group)
        $null = $account.Link.Add($path.Link)
    }

    foreach ($dn in $merged.Keys) {
        $account = $merged[$dn]
        [PSCustomObject]@{
            DistinguishedName = $dn
            Kind              = $account.Entry.Kind
            Item              = $account.Entry.Item
            Group             = [string[]]@($account.Group)
            Link              = [string[]]@($account.Link)
        }
    }
}
