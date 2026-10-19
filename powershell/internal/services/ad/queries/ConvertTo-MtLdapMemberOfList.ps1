function ConvertTo-MtLdapMemberOfList {
    <#
    .SYNOPSIS
    Returns the memberOf values of a search entry as a list, or $null when they are incomplete.

    .DESCRIPTION
    When an attribute has more values than the server returns at once, the search entry holds
    them under a ranged name (memberOf;range=0-...) and only part of them. That partial list is
    unknown rather than complete, so $null is returned. Otherwise the values are returned as a
    string array, empty when there is none.

    .PARAMETER Entry
    The search entry, as returned by Invoke-MtLdapSearch.

    .EXAMPLE
    ConvertTo-MtLdapMemberOfList -Entry $entry

    Returns the parent groups of the entry.
    #>
    [CmdletBinding()]
    [OutputType([string[]], [object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $Entry
    )

    if (@($Entry.PSObject.Properties.Name -match '^memberOf;range=').Count -gt 0) {
        return $null
    }
    return , [string[]]@($Entry.memberOf | Where-Object { $null -ne $_ })
}
