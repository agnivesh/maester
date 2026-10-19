function Read-MtAnssiAdAuthenticationSilo {
    <#
    .SYNOPSIS
    Reads whether an authentication policy silo is enforced and which accounts it holds.

    .DESCRIPTION
    Reads the name and msDS-AuthNPolicySiloEnforced of a silo with a base-scope LDAP search, and
    its msDS-AuthNPolicySiloMembers (the accounts granted access to it) with ranged reads. A silo
    whose enforced flag is not TRUE only audits. Throws when the silo cannot be read.

    .PARAMETER Connection
    The LDAP connection to use.

    .PARAMETER DistinguishedName
    The distinguished name of the silo.

    .EXAMPLE
    Read-MtAnssiAdAuthenticationSilo -Connection $connection -DistinguishedName $siloDn

    Returns an object with Name, Enforced and Member (a case-insensitive set of names).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection] $Connection,

        [Parameter(Mandatory)]
        [string] $DistinguishedName
    )

    $entry = Invoke-MtLdapSearch -Connection $Connection -SearchBase $DistinguishedName `
        -Scope Base -PageSize 0 -Attributes @('name', 'msDS-AuthNPolicySiloEnforced') |
        Select-Object -First 1
    if ($null -eq $entry) {
        throw "The authentication policy silo '$DistinguishedName' could not be read."
    }

    $member = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $memberDn = @(Get-MtLdapRangedValue -Connection $Connection `
            -DistinguishedName $DistinguishedName -AttributeName 'msDS-AuthNPolicySiloMembers')
    foreach ($dn in $memberDn) {
        $null = $member.Add([string]$dn)
    }

    return [PSCustomObject]@{
        Name     = [string]$entry.name
        Enforced = [string]$entry.'msDS-AuthNPolicySiloEnforced' -eq 'TRUE'
        Member   = $member
    }
}
