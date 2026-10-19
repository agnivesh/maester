function Get-MtAnssiAdCertificateFinding {
    <#
    .SYNOPSIS
    Lists the weak certificates held by directory objects, most severe first.

    .DESCRIPTION
    Judges every certificate of every object with Get-MtAnssiAdCertificateProblem and returns one
    row per certificate that has a problem: the object's distinguished name, the certificate's
    subject, expiry date (expired certificates are judged too) and problems, and the most severe
    level. Rows are sorted by level, then distinguished name, then subject.

    .PARAMETER Object
    The objects read by Get-MtAnssiAdCaCertificate, each with DistinguishedName and Certificate.

    .EXAMPLE
    Get-MtAnssiAdCertificateFinding -Object $objects

    Returns the weak certificates.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Object
    )

    $rows = foreach ($item in $Object) {
        foreach ($certificate in $item.Certificate) {
            $assessment = Get-MtAnssiAdCertificateProblem -Certificate $certificate
            if ($null -eq $assessment.Level) { continue }
            [PSCustomObject]@{
                DistinguishedName = $item.DistinguishedName
                Subject           = $assessment.Subject
                NotAfter          = $assessment.NotAfter
                Problem           = $assessment.Problem
                Level             = $assessment.Level
            }
        }
    }
    return @($rows | Sort-Object -Property Level, DistinguishedName, Subject)
}
