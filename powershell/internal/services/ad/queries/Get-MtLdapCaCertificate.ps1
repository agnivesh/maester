function Get-MtLdapCaCertificate {
    <#
    .SYNOPSIS
    Reads the certificates stored in the cACertificate attribute of directory objects below a base.

    .DESCRIPTION
    Searches below the base for objects that carry a cACertificate value (certification
    authorities, the AIA objects, the NTAuth store, enrollment services) and returns, for each
    object, its distinguished name, its name and the raw certificate values (one byte array per
    certificate, read from the raw search result so that binary values are never decoded as
    text). Unlike most collectors, it does not catch errors: a failed search throws, so that a
    caller never mistakes it for a forest without certificates.

    .PARAMETER Connection
    The LDAP connection to use.

    .PARAMETER SearchBase
    The distinguished name to search below, for example the Services container of the
    Configuration partition.

    .EXAMPLE
    Get-MtLdapCaCertificate -Connection $connection -SearchBase 'CN=Services,CN=Configuration,DC=x'

    Returns one object per directory object with DistinguishedName, Name and Certificate.
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
            -Scope Subtree -Filter '(cACertificate=*)' `
            -Attributes @('distinguishedName', 'name', 'cACertificate') -ReturnDirectoryEntry)
    foreach ($entry in $entries) {
        $certificate = @()
        $raw = $entry.DirectoryEntry.Attributes
        if ($raw.Contains('cACertificate')) {
            $certificate = @($raw['cACertificate'].GetValues([byte[]]))
        }
        [PSCustomObject]@{
            DistinguishedName = [string]$entry.DistinguishedName
            Name              = [string]$entry.name
            Certificate       = $certificate
        }
    }
}
