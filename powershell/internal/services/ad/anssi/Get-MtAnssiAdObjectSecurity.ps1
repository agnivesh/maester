function Get-MtAnssiAdObjectSecurity {
    <#
    .SYNOPSIS
    Reads the owner and DACL entries of the given directory objects, once per session.

    .DESCRIPTION
    Reads each object with one base-scope search (Get-MtLdapObjectSecurity) over a single
    connection and keeps the result in the session's AD cache, so a later call for the same
    object and extra attributes does not read it again; Clear-MtADCache resets it. Results come
    back in the order of the names given. Throws when a search fails or returns nothing for an
    object, so that a failed read is never reported as a harmless DACL. An object whose
    descriptor the server did not return comes back with Ace $null: the caller decides.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .PARAMETER DistinguishedName
    The objects to read.

    .PARAMETER Attribute
    Extra attributes to read with each object.

    .EXAMPLE
    Get-MtAnssiAdObjectSecurity -ProtocolEvidence $adState.ProtocolEvidence `
        -DistinguishedName "CN=AdminSDHolder,CN=System,$domainDn"

    Returns the owner and DACL entries of the AdminSDHolder object.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $ProtocolEvidence,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $DistinguishedName,

        [string[]] $Attribute = @()
    )

    $prefix = "AnssiObjectSecurity:$($ProtocolEvidence.ResolvedServer):$($Attribute -join ','):"
    $missing = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $DistinguishedName) {
        if (-not $__MtSession.ADCache.ContainsKey($prefix + $name)) {
            $null = $missing.Add($name)
        }
    }

    if ($missing.Count -gt 0) {
        $connection = $null
        try {
            $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
            foreach ($name in $missing) {
                $record = @(Get-MtLdapObjectSecurity -Connection $connection -SearchBase $name `
                        -Attribute $Attribute)
                if ($record.Count -eq 0) {
                    throw "The security descriptor of '$name' could not be read: " +
                    'no object returned.'
                }
                $__MtSession.ADCache[$prefix + $name] = $record[0]
            }
        } finally {
            if ($null -ne $connection) {
                $connection.Dispose()
            }
        }
    }

    foreach ($name in $DistinguishedName) {
        $__MtSession.ADCache[$prefix + $name]
    }
}
