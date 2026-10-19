function Get-MtLdapObjectOwner {
    <#
    .SYNOPSIS
    Reads the owner of the users, computers, groups, organizational units and GPOs of a domain.

    .DESCRIPTION
    Searches the domain for user objects (which include computers and managed service
    accounts), groups, organizational units and group policy containers, and asks only for the
    owner part of their security descriptor. Returns the distinguished name, name, most specific
    class, creation date and owner SID of each object. Unlike most collectors, it does not catch
    errors: a failed search throws, so that a caller never mistakes it for an empty result.

    .PARAMETER Connection
    The LDAP connection to use.

    .PARAMETER SearchBase
    The distinguished name of the domain.

    .EXAMPLE
    Get-MtLdapObjectOwner -Connection $connection -SearchBase $rootDse.DefaultNamingContext

    Returns one object per user, computer, group, organizational unit and GPO.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection] $Connection,

        [Parameter(Mandatory)]
        [string] $SearchBase
    )

    $filter = '(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)' +
        '(objectClass=groupPolicyContainer))'
    $attributes = @('distinguishedName', 'name', 'objectClass', 'whenCreated',
        'nTSecurityDescriptor')
    $entries = @(Invoke-MtLdapSearch -Connection $Connection -SearchBase $SearchBase `
            -Scope Subtree -Filter $filter -Attributes $attributes `
            -SecurityDescriptorFlags ([System.DirectoryServices.SecurityMasks]::Owner))
    foreach ($entry in $entries) {
        [PSCustomObject]@{
            DistinguishedName = [string]$entry.DistinguishedName
            Name              = [string]$entry.name
            ObjectClass       = [string]@($entry.objectClass)[-1]
            Created           = $entry.whenCreated
            OwnerSid          = Get-MtLdapSecurityDescriptorOwnerSid `
                -Descriptor $entry.nTSecurityDescriptor
        }
    }
}
