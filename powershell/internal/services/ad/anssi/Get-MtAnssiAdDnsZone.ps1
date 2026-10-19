function Get-MtAnssiAdDnsZone {
    <#
    .SYNOPSIS
    Reads the DNS zones stored in Active Directory below several bases, once per session.

    .DESCRIPTION
    Runs Get-MtLdapDnsZone below each base over a single connection and returns every zone once,
    even when two bases overlap. The result is kept in the session's AD cache, keyed by server and
    bases; Clear-MtADCache resets it. Throws when a search fails.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .PARAMETER SearchBase
    The distinguished names to search below.

    .EXAMPLE
    Get-MtAnssiAdDnsZone -ProtocolEvidence $evidence -SearchBase @("CN=System,$domainDn")

    Returns the zones stored in the domain naming context.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $ProtocolEvidence,

        [Parameter(Mandatory)]
        [string[]] $SearchBase
    )

    $cacheKey = "AnssiDnsZone:$($ProtocolEvidence.ResolvedServer):$($SearchBase -join ';')"
    if (-not $__MtSession.ADCache.ContainsKey($cacheKey)) {
        $seen = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        $found = [System.Collections.Generic.List[object]]::new()
        $connection = $null
        try {
            $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
            foreach ($name in $SearchBase) {
                foreach ($zone in @(Get-MtLdapDnsZone -Connection $connection -SearchBase $name)) {
                    if ($seen.Add($zone.DistinguishedName)) { $found.Add($zone) }
                }
            }
        } finally {
            if ($null -ne $connection) {
                $connection.Dispose()
            }
        }
        $__MtSession.ADCache[$cacheKey] = $found.ToArray()
    }

    return $__MtSession.ADCache[$cacheKey]
}
