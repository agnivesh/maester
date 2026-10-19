function Get-MtAnssiAdServer {
    <#
    .SYNOPSIS
    Finds the server and cluster computer accounts of the domain.

    .DESCRIPTION
    A computer account is a cluster account when one of its service principal names starts with
    MSClusterVirtualServer/: the cluster name account and the accounts of clustered services or
    applications carry it. A computer account that is neither a cluster account nor a domain
    controller is a server when its operating system name contains Server.

    Disabled accounts are returned too, the callers decide what to do with them. The computer
    accounts are read in one plain loop: directories can hold hundreds of thousands of computers.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .PARAMETER DomainController
    The domain controller entries, as collected for the DomainControllers category.

    .EXAMPLE
    Get-MtAnssiAdServer -Computer $computers -DomainController $entries

    Returns the server accounts in Server and the cluster accounts in Cluster.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Computer,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $DomainController
    )

    $controllerNames = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($controller in @(Get-MtAnssiAdDomainController -Computer $Computer `
                -DomainController $DomainController)) {
        $null = $controllerNames.Add([string]$controller.Computer.DistinguishedName)
    }

    $servers = [System.Collections.Generic.List[object]]::new()
    $clusters = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Computer) {
        if (@(@($item.ServicePrincipalName) -like 'MSClusterVirtualServer/*').Count -gt 0) {
            $clusters.Add($item)
        } elseif ($controllerNames.Contains([string]$item.DistinguishedName)) {
            continue
        } elseif ([string]$item.OperatingSystem -like '*Server*') {
            $servers.Add($item)
        }
    }

    Write-Verbose "Servers: $($servers.Count), cluster accounts: $($clusters.Count)"
    return [PSCustomObject]@{
        Server  = $servers.ToArray()
        Cluster = $clusters.ToArray()
    }
}
