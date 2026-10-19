function Get-MtAnssiAdObsoleteDomainController {
    <#
    .SYNOPSIS
    Finds the domain controllers whose operating system is past its end of support.

    .DESCRIPTION
    Looks up the operating system of each domain controller computer account in the table of
    Get-MtAnssiAdOperatingSystemSupport. A controller is obsolete when the end of support of its
    version is before Today. A controller whose operating system is empty or not in the table is
    only counted in UnknownCount.

    .PARAMETER Controller
    The domain controllers, as returned by Get-MtAnssiAdDomainController.

    .PARAMETER Today
    The date to compare the end of support with.

    .EXAMPLE
    Get-MtAnssiAdObsoleteDomainController -Controller $list -Today (Get-Date).Date

    Returns the obsolete controllers in Obsolete and the number of unrecognized ones in
    UnknownCount.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Controller,

        [Parameter(Mandatory)]
        [datetime] $Today
    )

    $obsolete = [System.Collections.Generic.List[object]]::new()
    $unknownCount = 0

    foreach ($item in $Controller) {
        $operatingSystem = [string]$item.Computer.OperatingSystem
        $support = Get-MtAnssiAdOperatingSystemSupport -OperatingSystem $operatingSystem
        if ($null -eq $support) {
            $unknownCount++
        } elseif ($support.EndOfSupport -lt $Today) {
            $obsolete.Add([PSCustomObject]@{
                    Name            = $item.Computer.Name
                    Type            = $item.Type
                    OperatingSystem = $operatingSystem
                    EndOfSupport    = $support.EndOfSupport
                })
        }
    }

    return [PSCustomObject]@{
        Obsolete     = $obsolete.ToArray()
        UnknownCount = $unknownCount
    }
}
