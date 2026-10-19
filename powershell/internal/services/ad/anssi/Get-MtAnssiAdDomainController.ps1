function Get-MtAnssiAdDomainController {
    <#
    .SYNOPSIS
    Finds the computer accounts of the domain controllers of the domain.

    .DESCRIPTION
    A computer account is a domain controller when its primary group is Domain Controllers (516,
    writable) or Read-only Domain Controllers (521), or when a domain controller entry of the
    configuration partition points to it through its server reference. A computer with the read-only
    primary group is a ReadOnly domain controller, any other one is Writable.

    The computer accounts are read in one plain loop: directories can hold hundreds of thousands of
    computers and a script block per account is several times slower.

    Domain controller entries of other domains of the forest have no computer account in the
    collected data and are not returned.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .PARAMETER DomainController
    The domain controller entries, as collected for the DomainControllers category.

    .EXAMPLE
    Get-MtAnssiAdDomainController -Computer $computers -DomainController $entries

    Returns one object per domain controller with its Type, its Computer account and its
    DomainController entry, which is null when no entry points to the computer.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Computer,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $DomainController
    )

    $writablePrimaryGroupId = 516
    $readOnlyPrimaryGroupId = 521

    $entryByComputer = @{}
    foreach ($entry in $DomainController) {
        $reference = [string]$entry.ServerReference
        if ($reference) {
            $entryByComputer[$reference] = $entry
        }
    }

    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Computer) {
        $entry = $entryByComputer[[string]$item.DistinguishedName]
        $primaryGroupId = $item.PrimaryGroupId

        if ($primaryGroupId -eq $readOnlyPrimaryGroupId) {
            $type = 'ReadOnly'
        } elseif ($primaryGroupId -eq $writablePrimaryGroupId -or $null -ne $entry) {
            $type = 'Writable'
        } else {
            continue
        }

        $found.Add([PSCustomObject]@{
                Type             = $type
                Computer         = $item
                DomainController = $entry
            })
    }

    Write-Verbose "Domain controller computer accounts found: $($found.Count)"
    return $found.ToArray()
}
