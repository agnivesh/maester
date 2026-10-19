function Get-MtAnssiAdApprovalNote {
    <#
    .SYNOPSIS
    Names the reported templates that need an approval before a certificate is issued.

    .DESCRIPTION
    A template that holds all requests for a CA manager, or asks for authorized signatures, delays
    the attack until the request is approved, but ANSSI does not exclude it, so it is still
    reported. When some findings are for such templates, returns a note that starts with a blank
    line and names each of them once, in alphabetical order. Returns an empty string otherwise.

    .PARAMETER Finding
    The rows of Get-MtAnssiAdEnrollmentFinding.

    .EXAMPLE
    Get-MtAnssiAdApprovalNote -Finding $findings

    Returns the note, or an empty string when no reported template needs an approval.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Finding
    )

    $held = @($Finding | Where-Object { $_.ApprovalRequired } | ForEach-Object { $_.Name } |
            Sort-Object -Unique)
    if ($held.Count -eq 0) { return '' }

    return "`n`nRequests for these templates need manager approval or authorized signatures " +
        "before a certificate is issued: $($held -join ', '). They are still listed, because " +
        'ANSSI does not exclude them.'
}
