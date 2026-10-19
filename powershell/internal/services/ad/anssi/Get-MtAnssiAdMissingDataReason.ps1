function Get-MtAnssiAdMissingDataReason {
    <#
    .SYNOPSIS
    Returns the reason to skip a test when a collection it needs was not returned, or nothing.

    .DESCRIPTION
    When a read of the directory fails, Get-MtADDomainState leaves the property of that collection
    $null. An empty collection is a valid answer: it means the directory holds none. A test that
    treats $null as empty would pass although it checked nothing, so it asks this function first and
    skips with the reason it returns.

    .PARAMETER State
    The state returned by Get-MtADDomainState.

    .PARAMETER Name
    The names of the collections the test reads, for example Users or Computers.

    .EXAMPLE
    Get-MtAnssiAdMissingDataReason -State $adState -Name 'Users', 'Computers'

    Returns $null when both collections were read, otherwise a sentence that names the missing ones.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object] $State,

        [Parameter(Mandatory)]
        [string[]] $Name
    )

    $missing = @($Name | Where-Object { $null -eq $State.$_ })
    if ($missing.Count -eq 0) {
        return $null
    }

    $names = $missing -join ', '
    return "The directory data could not be read: $names not returned by the domain controller."
}
