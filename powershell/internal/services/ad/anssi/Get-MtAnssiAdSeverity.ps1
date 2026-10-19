function Get-MtAnssiAdSeverity {
    <#
    .SYNOPSIS
    Converts ANSSI grades to a Maester severity.

    .DESCRIPTION
    ANSSI rates a finding from grade 1 (most severe) to grade 4. Some findings can be rated at
    several grades depending on what is found. When several grades are given, the most severe one,
    that is the lowest number, decides the severity.

    The severities are 1 Critical, 2 High, 3 Medium and 4 Low.

    .PARAMETER Grade
    One or more ANSSI grades, from 1 to 4.

    .EXAMPLE
    Get-MtAnssiAdSeverity -Grade 3, 4

    Returns Medium, the severity of the most severe grade.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 4)]
        [int[]] $Grade
    )

    $severityByGrade = @{ 1 = 'Critical'; 2 = 'High'; 3 = 'Medium'; 4 = 'Low' }
    $worstGrade = ($Grade | Measure-Object -Minimum).Minimum
    Write-Verbose "Most severe ANSSI grade: $worstGrade"

    return $severityByGrade[[int]$worstGrade]
}
