function Get-MtAnssiAdTemplateFinding {
    <#
    .SYNOPSIS
    Turns the dangerous rights found on certificate templates into ANSSI findings.

    .DESCRIPTION
    Keeps the rights that let a principal change a template and gives each its level: 1 when the
    template is published (named in the certificateTemplates attribute of an enrollment service,
    so a CA issues certificates from it) and the right is level 1 in the control table, 2
    otherwise. AllExtendedRights is left out: on a template it grants enrollment, not control.
    Template names are compared without regard to case.

    .PARAMETER Row
    The rows of Get-MtAnssiAdAceControl for the template objects.

    .PARAMETER EnrollmentService
    The enrollment service objects, with certificateTemplates in their Attribute dictionary.

    .EXAMPLE
    Get-MtAnssiAdTemplateFinding -Row $rows -EnrollmentService $services

    Returns the rows to report, with Level and Published set.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Row,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $EnrollmentService
    )

    $published = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($service in $EnrollmentService) {
        foreach ($name in $service.Attribute['certificateTemplates']) {
            $null = $published.Add([string]$name)
        }
    }

    foreach ($item in $Row) {
        if ($item.Control -eq 'AllExtendedRights') { continue }
        $isPublished = $published.Contains([string]$item.Name)
        $level = 2
        if ($isPublished -and $item.Level -eq 1) { $level = 1 }
        [PSCustomObject]@{
            DistinguishedName = $item.DistinguishedName
            Name              = $item.Name
            Sid               = $item.Sid
            Control           = $item.Control
            Level             = $level
            IsInherited       = $item.IsInherited
            Published         = $isPublished
        }
    }
}
