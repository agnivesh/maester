function Get-MtAnssiAdSearchSecurity {
    <#
    .SYNOPSIS
    Searches below directory objects and reads the owner and DACL entries found, once per session.

    .DESCRIPTION
    Runs one Get-MtLdapObjectSecurity search per base, with the same scope, filter and extra
    attributes, over a single connection, and returns every object found. The result is kept in
    the session's AD cache, keyed by server, bases, scope, filter and attributes;
    Clear-MtADCache resets it. A base without a matching object gives nothing. Throws when a
    search fails, for example when a base does not exist.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .PARAMETER SearchBase
    The distinguished names to search below.

    .PARAMETER Scope
    OneLevel or Subtree.

    .PARAMETER Filter
    The LDAP filter.

    .PARAMETER Attribute
    Extra attributes to read with each object.

    .EXAMPLE
    Get-MtAnssiAdSearchSecurity -ProtocolEvidence $evidence -SearchBase "CN=System,$domainDn" `
        -Scope OneLevel -Filter '(objectClass=secret)'

    Returns the secret objects of the System container with their owner and DACL.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $ProtocolEvidence,

        [Parameter(Mandatory)]
        [string[]] $SearchBase,

        [Parameter(Mandatory)]
        [ValidateSet('OneLevel', 'Subtree')]
        [string] $Scope,

        [Parameter(Mandatory)]
        [string] $Filter,

        [string[]] $Attribute = @()
    )

    $cacheKey = "AnssiSearchSecurity:$($ProtocolEvidence.ResolvedServer):" +
        "$($SearchBase -join ';'):$($Scope):$($Filter):$($Attribute -join ',')"
    if (-not $__MtSession.ADCache.ContainsKey($cacheKey)) {
        $found = [System.Collections.Generic.List[object]]::new()
        $connection = $null
        try {
            $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
            foreach ($name in $SearchBase) {
                $items = @(Get-MtLdapObjectSecurity -Connection $connection -SearchBase $name `
                        -Scope $Scope -Filter $Filter -Attribute $Attribute)
                foreach ($item in $items) { $found.Add($item) }
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
