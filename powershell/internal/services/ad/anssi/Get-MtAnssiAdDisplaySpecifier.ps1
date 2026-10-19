function Get-MtAnssiAdDisplaySpecifier {
    <#
    .SYNOPSIS
    Returns the display specifiers of the forest, read once per session.

    .DESCRIPTION
    Reads the display specifiers of the forest with Get-MtLdapDisplaySpecifier over a new LDAP
    connection and keeps them in the AD cache of the session, one entry per domain controller;
    Clear-MtADCache drops them. Throws when a read fails.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdDisplaySpecifier -ProtocolEvidence $adState.ProtocolEvidence

    Returns the display specifiers.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $cacheKey = "AnssiDisplaySpecifier:$($ProtocolEvidence.ResolvedServer)"
    if (-not $__MtSession.ADCache.ContainsKey($cacheKey)) {
        $connection = $null
        try {
            $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
            $rootDse = Get-MtLdapRootDse -Connection $connection
            $__MtSession.ADCache[$cacheKey] = @(Get-MtLdapDisplaySpecifier -Connection $connection `
                    -ConfigurationNamingContext $rootDse.ConfigurationNamingContext)
        } finally {
            if ($null -ne $connection) {
                $connection.Dispose()
            }
        }
    }

    return $__MtSession.ADCache[$cacheKey]
}
