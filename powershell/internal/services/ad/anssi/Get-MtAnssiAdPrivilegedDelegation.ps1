function Get-MtAnssiAdPrivilegedDelegation {
    <#
    .SYNOPSIS
    Finds the accounts allowed to delegate to a domain controller or to the krbtgt service.

    .DESCRIPTION
    Constrained delegation lets an account request service tickets on behalf of a user to the
    services named in its msDS-AllowedToDelegateTo attribute. Returns one object for each enabled
    user or computer account that names a privileged service there: a service on a domain
    controller (the host part of the service principal name is the DNS name or the short name of
    a domain controller), or the krbtgt service.

    Each result tells whether the account also has protocol transition
    (TRUSTED_TO_AUTH_FOR_DELEGATION), which lets it act on behalf of any user without that user
    authenticating first. Names are compared without regard to case.

    .PARAMETER User
    The user accounts, as collected for the Users category.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .PARAMETER Controller
    The domain controllers, as returned by Get-MtAnssiAdDomainController.

    .EXAMPLE
    Get-MtAnssiAdPrivilegedDelegation -User $users -Computer $computers -Controller $controllers

    Returns the accounts with their privileged delegation targets.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object[]] $User,

        [AllowNull()]
        [object[]] $Computer,

        [AllowNull()]
        [object[]] $Controller
    )

    $controllerHost = @{}
    foreach ($item in $Controller) {
        foreach ($name in @($item.Computer.DnsHostName, $item.Computer.Name)) {
            if ($name) { $controllerHost[[string]$name] = $true }
        }
    }

    $accounts = @($User | ForEach-Object { @{ Item = $_; Kind = 'User' } }) +
        @($Computer | ForEach-Object { @{ Item = $_; Kind = 'Computer' } })
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($account in $accounts) {
        $item = $account.Item
        if ($item.Enabled -ne $true) {
            continue
        }

        $targets = @(Select-MtAnssiAdPrivilegedSpn -ServicePrincipalName $item.AllowedToDelegateTo `
                -ControllerHost $controllerHost)
        if ($targets.Count -gt 0) {
            $found.Add([PSCustomObject]@{
                    DistinguishedName  = $item.DistinguishedName
                    Name               = $item.Name
                    Kind               = $account.Kind
                    ProtocolTransition = $item.TrustedToAuthForDelegation -eq $true
                    Target             = $targets
                })
        }
    }

    return $found.ToArray()
}
