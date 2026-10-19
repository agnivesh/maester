function Get-MtLdapObjectSecurity {
    <#
    .SYNOPSIS
    Reads the owner and DACL entries of directory objects.

    .DESCRIPTION
    Searches below a base (or reads the base object alone) and asks for the owner and DACL part of
    each object's security descriptor. The descriptor is read from the raw search result, so it
    is parsed byte by byte on every platform. Returns the distinguished name, name, every object
    class, the owner SID, the DACL entries (see Get-MtLdapSecurityDescriptorAce) and the values of
    any extra attributes asked for. Ace is $null when the server returned no descriptor, which
    is what Active Directory does when the reading account may not see it. Unlike most
    collectors, it does not catch errors: a failed search or a malformed descriptor throws, so
    that a caller never mistakes it for an empty or harmless result.

    .PARAMETER Connection
    The LDAP connection to use.

    .PARAMETER SearchBase
    The distinguished name to read or search below.

    .PARAMETER Scope
    Base, OneLevel or Subtree. Base by default.

    .PARAMETER Filter
    The LDAP filter. Every object by default.

    .PARAMETER Attribute
    Extra attributes to return, in the Attribute dictionary of each result.

    .EXAMPLE
    Get-MtLdapObjectSecurity -Connection $connection -SearchBase 'CN=AdminSDHolder,CN=System,DC=x'

    Returns the owner and DACL entries of the AdminSDHolder object.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection] $Connection,

        [Parameter(Mandatory)]
        [string] $SearchBase,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string] $Scope = 'Base',

        [string] $Filter = '(objectClass=*)',

        [string[]] $Attribute = @()
    )

    $flags = [System.DirectoryServices.SecurityMasks]::Owner -bor
    [System.DirectoryServices.SecurityMasks]::Dacl
    $attributes = @('distinguishedName', 'name', 'objectClass', 'nTSecurityDescriptor') + $Attribute
    $pageSize = 1000
    if ($Scope -eq 'Base') { $pageSize = 0 }
    $entries = @(Invoke-MtLdapSearch -Connection $Connection -SearchBase $SearchBase -Scope $Scope `
            -Filter $Filter -Attributes $attributes -PageSize $pageSize `
            -SecurityDescriptorFlags $flags -ReturnDirectoryEntry)
    foreach ($entry in $entries) {
        $descriptor = $null
        $rawAttributes = $entry.DirectoryEntry.Attributes
        if ($null -ne $rawAttributes -and $rawAttributes.Contains('nTSecurityDescriptor')) {
            $descriptor = [byte[]](@($rawAttributes['nTSecurityDescriptor'].GetValues([byte[]]))[0])
        }
        $values = [ordered]@{}
        foreach ($name in $Attribute) { $values[$name] = $entry.$name }
        $ace = $null
        if ($null -ne $descriptor) {
            $ace = @(Get-MtLdapSecurityDescriptorAce -Descriptor $descriptor)
        }
        [PSCustomObject]@{
            DistinguishedName = [string]$entry.DistinguishedName
            Name              = [string]$entry.name
            ObjectClass       = [string[]]@($entry.objectClass)
            OwnerSid          = Get-MtLdapSecurityDescriptorOwnerSid -Descriptor $descriptor
            Ace               = $ace
            Attribute         = $values
        }
    }
}
