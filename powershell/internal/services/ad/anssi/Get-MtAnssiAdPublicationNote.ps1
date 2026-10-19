function Get-MtAnssiAdPublicationNote {
    <#
    .SYNOPSIS
    Names the reported templates that a CA trusted for logon publishes.

    .DESCRIPTION
    A template that a CA trusted for logon publishes can be used for the attack today; the others
    are reported because they would be as soon as such a CA publishes them. When some findings are
    for published templates, returns a note that starts with a blank line and names each of them
    once, in alphabetical order. Returns an empty string otherwise.

    .PARAMETER Finding
    The rows of Get-MtAnssiAdEnrollmentFinding.

    .EXAMPLE
    Get-MtAnssiAdPublicationNote -Finding $findings

    Returns the note, or an empty string when no reported template is published that way.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Finding
    )

    $live = @($Finding | Where-Object { $_.Trusted } | ForEach-Object { $_.Name } |
            Sort-Object -Unique)
    if ($live.Count -eq 0) { return '' }

    return "`n`nA CA trusted for logon publishes these templates, so the attack works today: " +
        "$($live -join ', ')."
}
