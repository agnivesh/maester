function ConvertTo-MtAnssiAdMarkdownTable {
    <#
    .SYNOPSIS
    Builds a markdown table of findings for an ANSSI Active Directory test result.

    .DESCRIPTION
    The first column, Domain, is added to every table: it holds the domain of each finding, read
    from its DistinguishedName, so a scan of several domains (global catalog) stays readable. A
    finding without a DistinguishedName gets DefaultDomain, then the scanned domain, then a dash.

    Every header and every cell is escaped with Get-MtSafeMarkdown, because the values come from
    the directory (names, distinguished names, descriptions) and must not be rendered as markdown.
    A table is capped at MaxRow rows so a directory with thousands of findings does not produce a
    report of several megabytes.

    .PARAMETER InputObject
    The findings, one table row each.

    .PARAMETER Column
    An ordered dictionary of column header to script block. Each script block receives the finding
    as $_ and returns the cell value. Several values are joined with a comma.

    .PARAMETER DomainSource
    A script block that receives the finding as $_ and returns the distinguished name the Domain
    column is read from. Use it when the finding wraps the object, for example
    { $_.Item.DistinguishedName }. By default the DistinguishedName of the finding is used.

    .PARAMETER DefaultDomain
    The domain shown for a finding that has no DistinguishedName. When omitted, the scanned
    domain is used.

    .PARAMETER MaxRow
    The maximum number of rows shown. When there are more findings a line says how many are shown.

    .EXAMPLE
    ConvertTo-MtAnssiAdMarkdownTable -InputObject $users -Column ([ordered]@{ Name = { $_.Name } })

    Returns a one-column markdown table with the name of each user.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $InputObject,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Column,

        [scriptblock] $DomainSource = { $_.DistinguishedName },

        [string] $DefaultDomain,

        [ValidateRange(1, 10000)]
        [int] $MaxRow = 100
    )

    Write-Verbose "Building a table of $($InputObject.Count) finding(s), showing at most $MaxRow."

    $headers = @('Domain') + @($Column.Keys | ForEach-Object { Get-MtSafeMarkdown ([string]$_) })
    $separators = @('---') * $headers.Count
    $table = "| $($headers -join ' | ') |`n| $($separators -join ' | ') |`n"

    $fallbackDomain = $DefaultDomain
    $fallbackLoaded = -not [string]::IsNullOrEmpty($DefaultDomain)

    foreach ($item in ($InputObject | Select-Object -First $MaxRow)) {
        $dn = @($item | ForEach-Object -Process $DomainSource)[0]
        $domain = Get-MtAnssiAdDnDomain -DistinguishedName ([string]$dn)
        if ([string]::IsNullOrEmpty($domain) -and -not $fallbackLoaded) {
            $fallbackDomain = Get-MtAnssiAdScannedDomain
            $fallbackLoaded = $true
        }
        if ([string]::IsNullOrEmpty($domain)) { $domain = $fallbackDomain }
        if ([string]::IsNullOrEmpty($domain)) { $domain = '-' }

        $cells = @(Get-MtSafeMarkdown $domain)
        foreach ($name in $Column.Keys) {
            $value = @($item | ForEach-Object -Process $Column[$name]) -join ', '
            $cells += Get-MtSafeMarkdown $value
        }
        $table += "| $($cells -join ' | ') |`n"
    }

    if ($InputObject.Count -gt $MaxRow) {
        $table += "`nShowing the first $MaxRow of $($InputObject.Count).`n"
    }

    return $table
}
