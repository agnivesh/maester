function Get-MtAnssiAdNamingContextHead {
    <#
    .SYNOPSIS
    Returns the distinguished names of the naming contexts of the domain and forest.

    .DESCRIPTION
    Reads the RootDSE of the domain controller once per session and returns the heads of the
    domain, Configuration and Schema naming contexts, then the DomainDnsZones partition of the
    domain and the ForestDnsZones partition of the forest when the controller lists them. The
    result is kept in the session's AD cache; Clear-MtADCache resets it. Throws when the RootDSE
    cannot be read or names no domain, Configuration or Schema naming context.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdNamingContextHead -ProtocolEvidence $adState.ProtocolEvidence

    Returns, for example, DC=contoso,DC=com, CN=Configuration,DC=contoso,DC=com and so on.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $cacheKey = "AnssiNamingContextHead:$($ProtocolEvidence.ResolvedServer)"
    if (-not $__MtSession.ADCache.ContainsKey($cacheKey)) {
        $connection = $null
        try {
            $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
            $rootDse = Get-MtLdapRootDse -Connection $connection
        } finally {
            if ($null -ne $connection) {
                $connection.Dispose()
            }
        }

        $head = @($rootDse.DefaultNamingContext, $rootDse.ConfigurationNamingContext,
            $rootDse.SchemaNamingContext)
        if (@($head | Where-Object { $_ }).Count -ne 3) {
            throw 'The RootDSE does not name the domain, Configuration and Schema naming contexts.'
        }
        $dns = @("DC=DomainDnsZones,$($rootDse.DefaultNamingContext)",
            "DC=ForestDnsZones,$($rootDse.RootDomainNamingContext)")
        foreach ($name in $dns) {
            if ($rootDse.NamingContexts -contains $name) {
                $head += $name
            }
        }
        $__MtSession.ADCache[$cacheKey] = [string[]]$head
    }

    return $__MtSession.ADCache[$cacheKey]
}
