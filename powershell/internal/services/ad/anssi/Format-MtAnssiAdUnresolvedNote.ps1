function Format-MtAnssiAdUnresolvedNote {
    <#
    .SYNOPSIS
    Writes the sentence that says how many members of the protected groups were not checked.

    .DESCRIPTION
    Takes the Unresolved list returned by Get-MtAnssiAdPrivilegedAccount and returns a sentence,
    starting with a space, that says how many members of the protected groups are outside the
    collected data. Returns an empty string when there are none, so that the result can always be
    appended to a result text.

    .PARAMETER Unresolved
    The Unresolved list returned by Get-MtAnssiAdPrivilegedAccount.

    .EXAMPLE
    $summary + (Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved)

    Appends the note to a result text when some members were not checked.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object[]] $Unresolved
    )

    $count = @($Unresolved | Where-Object { $null -ne $_ }).Count
    if ($count -eq 0) {
        return ''
    }

    return " The protected groups also hold $count member(s) outside the collected data, such " +
        'as accounts or groups from another domain. Those were not checked.'
}
