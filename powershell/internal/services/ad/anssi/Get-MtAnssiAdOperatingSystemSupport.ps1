function Get-MtAnssiAdOperatingSystemSupport {
    <#
    .SYNOPSIS
    Returns the end of support of a Windows operating system.

    .DESCRIPTION
    Matches the operating system text of a computer account against a table of Windows versions
    and returns the version name and the last day on which Microsoft publishes security updates
    for it without a paid Extended Security Updates program. The dates are the end of extended
    support of the Microsoft Lifecycle pages, as calendar dates in US Pacific Time.

    Returns null when the operating system is empty or is not in the table, for example a
    Windows Server semi-annual channel release.

    .PARAMETER OperatingSystem
    The operatingSystem attribute of the computer account, for example Windows Server 2016 Standard.

    .EXAMPLE
    Get-MtAnssiAdOperatingSystemSupport -OperatingSystem 'Windows Server 2012 R2 Standard'

    Returns Name 'Windows Server 2012 R2' and EndOfSupport 2023-10-10.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $OperatingSystem
    )

    # Source: https://learn.microsoft.com/lifecycle/products/ (extended end date of each product).
    # The R2 rows come first so that the plain version does not match them. The leading commas
    # keep each row an array instead of letting the outer array flatten it.
    $table = @(
        ,@('Windows 2000', '2010-07-13')
        ,@('Windows Server 2003', '2015-07-14')
        ,@('Windows Server 2008 R2', '2020-01-14')
        ,@('Windows Server 2008', '2020-01-14')
        ,@('Windows Server 2012 R2', '2023-10-10')
        ,@('Windows Server 2012', '2023-10-10')
        ,@('Windows Server 2016', '2027-01-12')
        ,@('Windows Server 2019', '2029-01-09')
        ,@('Windows Server 2022', '2031-10-14')
        ,@('Windows Server 2025', '2034-11-14')
    )

    # Older versions store the trademark, as in "Windows Server(R) 2008 Standard".
    $trademarks = '\(R\)|{0}|{1}' -f [char]0x00AE, [char]0x2122
    $text = $OperatingSystem -replace $trademarks, ''
    $text = ($text -replace '\s+', ' ').Trim()

    foreach ($row in $table) {
        if ($text -match ('^' + [regex]::Escape($row[0]))) {
            return [PSCustomObject]@{
                Name         = $row[0]
                EndOfSupport = [datetime]::ParseExact($row[1], 'yyyy-MM-dd',
                    [System.Globalization.CultureInfo]::InvariantCulture)
            }
        }
    }

    return $null
}
