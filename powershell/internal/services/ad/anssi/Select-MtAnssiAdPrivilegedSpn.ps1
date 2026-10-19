function Select-MtAnssiAdPrivilegedSpn {
    <#
    .SYNOPSIS
    Keeps the service principal names that point to a domain controller or to krbtgt.

    .DESCRIPTION
    A service principal name has the form class/host[:port][/name]. A name is kept when its class
    is krbtgt, or when its host is one of the domain controller host names given. The comparison
    ignores case, because the lookup is a hashtable. A name without a host part matches no host.

    .PARAMETER ServicePrincipalName
    The service principal names to check.

    .PARAMETER ControllerHost
    A hashtable whose keys are the DNS names and short names of the domain controllers.

    .EXAMPLE
    Select-MtAnssiAdPrivilegedSpn -ServicePrincipalName $spns -ControllerHost $hosts

    Returns the names that target a domain controller or the krbtgt service.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowNull()]
        [string[]] $ServicePrincipalName,

        [Parameter(Mandatory)]
        [hashtable] $ControllerHost
    )

    foreach ($spn in $ServicePrincipalName) {
        $parts = ([string]$spn) -split '/'
        $hostName = ($parts[1] -split ':')[0]
        if ($parts[0] -eq 'krbtgt' -or $ControllerHost.ContainsKey($hostName)) {
            $spn
        }
    }
}
