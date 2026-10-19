function Get-MtAnssiAdControllerWithoutSysvolDfsr {
    <#
    .SYNOPSIS
    Finds the domain controllers that have no SYSVOL subscription of the DFS Replication service.

    .DESCRIPTION
    A domain controller that replicates SYSVOL with DFS Replication has a subscription object
    named CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings below its computer
    account. A controller without it does not replicate SYSVOL with DFS Replication: it still uses
    the obsolete File Replication Service (NTFRS), or its replication is broken.

    The distinguished names are compared without regard to case.

    .PARAMETER Controller
    The domain controllers, as returned by Get-MtAnssiAdDomainController.

    .PARAMETER Subscription
    The DFS Replication subscriptions, as collected for the DfsrSubscriptions category.

    .EXAMPLE
    Get-MtAnssiAdControllerWithoutSysvolDfsr -Controller $controllers -Subscription $subscriptions

    Returns the controllers without a SYSVOL subscription.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Controller,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Subscription
    )

    $subscriptionPrefix = 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,'

    $subscribed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Subscription) {
        $null = $subscribed.Add([string]$item.DistinguishedName)
    }

    $missing = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Controller) {
        $expected = $subscriptionPrefix + [string]$item.Computer.DistinguishedName
        if (-not $subscribed.Contains($expected)) {
            $missing.Add($item)
        }
    }

    return $missing.ToArray()
}
