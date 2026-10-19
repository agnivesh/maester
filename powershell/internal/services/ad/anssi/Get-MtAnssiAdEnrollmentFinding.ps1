function Get-MtAnssiAdEnrollmentFinding {
    <#
    .SYNOPSIS
    Turns enrollment rights on templates into ANSSI findings with a level.

    .DESCRIPTION
    Keeps the enrollment rights on templates that let the requester name a certificate used to log
    on (matched by distinguished name). ANSSI gives this finding level 1 only, so every right has
    level 1. Each row also says whether any CA publishes the template and whether a CA trusted for
    logon does, in which case the attack works today. Template names are compared without regard
    to case.

    .PARAMETER Right
    The rows of Get-MtAnssiAdEnrollmentRight.

    .PARAMETER Template
    The templates to judge, from Get-MtAnssiAdAuthenticationTemplate.

    .PARAMETER Publication
    The result of Get-MtAnssiAdTemplatePublication.

    .EXAMPLE
    Get-MtAnssiAdEnrollmentFinding -Right $rights -Template $templates -Publication $publication

    Returns the rows to report, with Level 1, Published, Trusted and ApprovalRequired set.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Right,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Template,

        [Parameter(Mandatory)]
        [object] $Publication
    )

    $judged = @{}
    foreach ($item in $Template) { $judged[$item.DistinguishedName] = $item }

    foreach ($row in $Right) {
        $template = $judged[$row.DistinguishedName]
        if ($null -eq $template) { continue }
        $trusted = $Publication.Trusted.Contains([string]$row.Name)
        [PSCustomObject]@{
            DistinguishedName = $row.DistinguishedName
            Name              = $row.Name
            Sid               = $row.Sid
            Control           = $row.Control
            Level             = 1
            IsInherited       = $row.IsInherited
            Published         = $Publication.Published.Contains([string]$row.Name)
            Trusted           = $trusted
            ApprovalRequired  = $template.ApprovalRequired
        }
    }
}
