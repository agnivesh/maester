function Format-MtAnssiAdAceControlTable {
    <#
    .SYNOPSIS
    Renders the dangerous rights found by Get-MtAnssiAdAceControl as a markdown table.

    .DESCRIPTION
    One line per right, the most severe first, then by object and trustee name. The trustee is
    shown by the account name (or the name) of the matching collected user, computer or group, by
    its usual name for Everyone, Authenticated Users and Anonymous Logon, or by its SID when it is
    not known (for example a deleted account or a principal of another domain). The table is capped
    by ConvertTo-MtAnssiAdMarkdownTable. When a trustee is an Exchange group, the note of
    Get-MtAnssiAdExchangeNote follows the table after a blank line.

    .PARAMETER Row
    The rows of Get-MtAnssiAdAceControl.

    .PARAMETER Principal
    The collected users, computers and groups, used to name the trustees.

    .EXAMPLE
    Format-MtAnssiAdAceControlTable -Row $rows -Principal @($adState.Users + $adState.Groups)

    Returns a table with the Domain, Object, Trustee, Right, Severity and Inherited columns.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Row,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Principal
    )

    $name = @{
        'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-7' = 'Anonymous Logon'
    }
    foreach ($item in $Principal) {
        $label = [string]$item.SamAccountName
        if (-not $label) { $label = [string]$item.Name }
        $name[[string]$item.Sid.Value] = $label
    }

    $view = foreach ($entry in $Row) {
        $trustee = $name[[string]$entry.Sid]
        if (-not $trustee) { $trustee = [string]$entry.Sid }
        [PSCustomObject]@{ Entry = $entry; Trustee = $trustee }
    }
    $sorted = @($view | Sort-Object -Property { $_.Entry.Level }, { $_.Entry.Name }, Trustee)
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $sorted `
        -DomainSource { $_.Entry.DistinguishedName } -Column ([ordered]@{
            'Object'    = { Get-MtAnssiAdDnRelative -DistinguishedName $_.Entry.Name }
            'Trustee'   = { $_.Trustee }
            'Right'     = { $_.Entry.Control }
            'Severity'  = { Get-MtAnssiAdSeverity -Grade $_.Entry.Level }
            'Inherited' = { if ($_.Entry.IsInherited) { 'Yes' } else { 'No' } }
        })
    $note = Get-MtAnssiAdExchangeNote -Trustee @($view.Trustee)
    if (-not $note) { return $table }
    return "$table`n$note"
}
