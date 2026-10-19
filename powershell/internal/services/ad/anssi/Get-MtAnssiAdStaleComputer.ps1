function Get-MtAnssiAdStaleComputer {
    <#
    .SYNOPSIS
    Finds the enabled computer accounts with an old date attribute.

    .DESCRIPTION
    Goes through the computer accounts once and skips the disabled ones. An enabled computer is
    stale when the chosen date attribute is before Cutoff. A computer without a value is stale only
    when NullIsStale is set.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .PARAMETER Attribute
    The date attribute of the computer account to check, PasswordLastSet or LastLogonDate.

    .PARAMETER Cutoff
    Computers whose date is before this date are stale.

    .PARAMETER NullIsStale
    Treat a computer without a value as stale.

    .EXAMPLE
    Get-MtAnssiAdStaleComputer -Computer $servers -Attribute PasswordLastSet -Cutoff $date

    Returns the number of enabled computers in EnabledCount and, in Stale, one object per stale
    computer with its Computer account and its Date.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Computer,

        [Parameter(Mandatory)]
        [ValidateSet('PasswordLastSet', 'LastLogonDate')]
        [string] $Attribute,

        [Parameter(Mandatory)]
        [datetime] $Cutoff,

        [switch] $NullIsStale
    )

    $enabledCount = 0
    $stale = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $Computer) {
        if ($item.Enabled -ne $true) { continue }
        $enabledCount++

        $date = $item.$Attribute
        if ($null -eq $date) {
            $isStale = [bool]$NullIsStale
        } else {
            $isStale = $date -lt $Cutoff
        }

        if ($isStale) {
            $stale.Add([PSCustomObject]@{
                    Computer = $item
                    Date     = $date
                })
        }
    }

    return [PSCustomObject]@{
        EnabledCount = $enabledCount
        Stale        = $stale.ToArray()
    }
}
