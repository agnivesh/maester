function Get-MtLdapDnsZone {
    <#
    .SYNOPSIS
    Reads the DNS zones stored in Active Directory below a base.

    .DESCRIPTION
    Searches below the base for dnsZone objects and returns, for each zone, its distinguished name,
    its name and the raw values of its dNSProperty attribute (one byte array per property, read
    from the raw search result so that binary values are never decoded as text). Unlike most
    collectors, it does not catch errors: a failed search throws, so that a caller never mistakes
    it for a domain without zones.

    .PARAMETER Connection
    The LDAP connection to use.

    .PARAMETER SearchBase
    The distinguished name to search below, for example the root of the DomainDnsZones partition.

    .EXAMPLE
    Get-MtLdapDnsZone -Connection $connection -SearchBase 'DC=DomainDnsZones,DC=contoso,DC=com'

    Returns one object per zone with DistinguishedName, Name and Property.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection] $Connection,

        [Parameter(Mandatory)]
        [string] $SearchBase
    )

    $entries = @(Invoke-MtLdapSearch -Connection $Connection -SearchBase $SearchBase `
        -Scope Subtree `
            -Filter '(objectClass=dnsZone)' `
                -Attributes @('distinguishedName', 'name', 'dNSProperty') `
            -ReturnDirectoryEntry)
    foreach ($entry in $entries) {
        $property = @()
        $raw = $entry.DirectoryEntry.Attributes
        if ($null -ne $raw -and $raw.Contains('dNSProperty')) {
            $property = @($raw['dNSProperty'].GetValues([byte[]]))
        }
        [PSCustomObject]@{
            DistinguishedName = [string]$entry.DistinguishedName
            Name              = [string]$entry.name
            Property          = $property
        }
    }
}
