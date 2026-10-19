function ConvertTo-MtAnssiAdFunctionalLevel {
    <#
    .SYNOPSIS
    Converts a collected forest or domain mode to its functional level number.

    .DESCRIPTION
    The collector stores the mode as a name for the levels it knows (Windows2000Forest to
    Windows2016Forest, or the Domain equivalents) and as the plain number for newer levels, for
    example 10 for Windows Server 2025. This returns the number from 0 to 7 for a name, the number
    itself for a newer level, and nothing when the mode is missing or not recognized.

    Levels: 0 Windows 2000, 1 Windows Server 2003 interim, 2 Windows Server 2003,
    3 Windows Server 2008, 4 Windows Server 2008 R2, 5 Windows Server 2012,
    6 Windows Server 2012 R2, 7 Windows Server 2016.

    .PARAMETER Mode
    The ForestMode or DomainMode value of the collected state.

    .EXAMPLE
    ConvertTo-MtAnssiAdFunctionalLevel -Mode 'Windows2008R2Forest'

    Returns 4.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [AllowNull()]
        [object] $Mode
    )

    $levelByName = @{
        Windows2000        = 0
        Windows2003Interim = 1
        Windows2003        = 2
        Windows2008        = 3
        Windows2008R2      = 4
        Windows2012        = 5
        Windows2012R2      = 6
        Windows2016        = 7
    }
    $text = ([string]$Mode) -replace '(Forest|Domain)$', ''
    if ($levelByName.ContainsKey($text)) {
        return $levelByName[$text]
    }

    $number = 0
    if ([int]::TryParse($text, [ref]$number) -and $number -ge 0) {
        return $number
    }

    Write-Verbose "Functional level not recognized: $Mode"
    return $null
}
