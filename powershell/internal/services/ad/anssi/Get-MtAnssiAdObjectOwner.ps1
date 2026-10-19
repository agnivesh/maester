function Get-MtAnssiAdObjectOwner {
    <#
    .SYNOPSIS
    Returns the owners of the domain's objects, read once per session.

    .DESCRIPTION
    Reads the owner of the users, computers, groups, organizational units and GPOs of the domain
    with Get-MtLdapObjectOwner over a new LDAP connection and keeps the result in the AD cache of
    the session, one entry per domain controller; Clear-MtADCache drops it. Throws when a read
    fails.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdObjectOwner -ProtocolEvidence $adState.ProtocolEvidence

    Returns one object per user, computer, group, organizational unit and GPO.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $cacheKey = "AnssiObjectOwner:$($ProtocolEvidence.ResolvedServer)"
    if (-not $__MtSession.ADCache.ContainsKey($cacheKey)) {
        $connection = $null
        try {
            $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
            $rootDse = Get-MtLdapRootDse -Connection $connection
            $__MtSession.ADCache[$cacheKey] = @(Get-MtLdapObjectOwner -Connection $connection `
                    -SearchBase $rootDse.DefaultNamingContext)
        } finally {
            if ($null -ne $connection) {
                $connection.Dispose()
            }
        }
    }

    return $__MtSession.ADCache[$cacheKey]
}
