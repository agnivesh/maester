function Format-MtAnssiAdDate {
    <#
    .SYNOPSIS
    Formats a directory timestamp for an ANSSI Active Directory test result.

    .DESCRIPTION
    Returns the date as yyyy-MM-dd, or the text given in NullText when the directory holds no
    value, for example an account that never logged on.

    .PARAMETER Date
    The timestamp to format.

    .PARAMETER NullText
    The text returned when Date is null.

    .EXAMPLE
    Format-MtAnssiAdDate -Date $user.LastLogonDate

    Returns 2026-10-02 for a logon on that day, or Never when the account never logged on.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [Nullable[datetime]] $Date,

        [string] $NullText = 'Never'
    )

    if ($null -eq $Date) {
        return $NullText
    }

    return $Date.ToString('yyyy-MM-dd')
}
