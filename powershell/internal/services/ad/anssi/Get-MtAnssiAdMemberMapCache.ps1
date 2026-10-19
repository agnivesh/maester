function Get-MtAnssiAdMemberMapCache {
    <#
    .SYNOPSIS
    Returns the session's group member map for a domain controller.

    .DESCRIPTION
    The member map (group distinguished name to the distinguished names of its direct members)
    is kept in the AD cache of the session, one per domain controller, so that every ANSSI test
    reads each group's members once. Read-MtAnssiAdGroupMemberMap fills it. Clear-MtADCache
    drops it.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state; its ResolvedServer names the cache entry.

    .EXAMPLE
    $map = Get-MtAnssiAdMemberMapCache -ProtocolEvidence $adState.ProtocolEvidence

    Returns the hashtable to pass to Read-MtAnssiAdGroupMemberMap.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $cacheKey = "AnssiGroupMemberMap:$($ProtocolEvidence.ResolvedServer)"
    if (-not $__MtSession.ADCache.ContainsKey($cacheKey)) {
        $__MtSession.ADCache[$cacheKey] = @{}
    }
    return $__MtSession.ADCache[$cacheKey]
}
