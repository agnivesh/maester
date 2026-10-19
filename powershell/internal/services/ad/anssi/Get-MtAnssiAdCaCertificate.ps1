function Get-MtAnssiAdCaCertificate {
    <#
    .SYNOPSIS
    Reads the certificates stored in Active Directory below a base, once per session.

    .DESCRIPTION
    Runs Get-MtLdapCaCertificate below the base over its own connection. The result is kept in
    the session's AD cache, keyed by server and base; Clear-MtADCache resets it. Throws when the
    search fails.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .PARAMETER SearchBase
    The distinguished name to search below.

    .EXAMPLE
    Get-MtAnssiAdCaCertificate -ProtocolEvidence $evidence -SearchBase "CN=Services,$configDn"

    Returns the objects of the Services container that hold certificates.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $ProtocolEvidence,

        [Parameter(Mandatory)]
        [string] $SearchBase
    )

    $cacheKey = "AnssiCaCertificate:$($ProtocolEvidence.ResolvedServer):$SearchBase"
    if (-not $__MtSession.ADCache.ContainsKey($cacheKey)) {
        $connection = $null
        try {
            $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
            $found = @(Get-MtLdapCaCertificate -Connection $connection -SearchBase $SearchBase)
        } finally {
            if ($null -ne $connection) {
                $connection.Dispose()
            }
        }
        $__MtSession.ADCache[$cacheKey] = $found
    }

    return $__MtSession.ADCache[$cacheKey]
}
