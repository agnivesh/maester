function Get-MtLdapDisplaySpecifier {
    <#
    .SYNOPSIS
    Reads the display specifiers of the forest with their context menu entries.

    .DESCRIPTION
    Searches CN=DisplaySpecifiers in the Configuration partition for displaySpecifier objects and
    returns their name and their adminContextMenu and shellContextMenu values, which can make the
    Active Directory consoles run a program. Unlike most collectors, it does not catch errors: a
    failed search throws, so that a caller never mistakes it for an empty list.

    .PARAMETER Connection
    The LDAP connection to use.

    .PARAMETER ConfigurationNamingContext
    The distinguished name of the Configuration partition.

    .EXAMPLE
    Get-MtLdapDisplaySpecifier -Connection $connection `
        -ConfigurationNamingContext $rootDse.ConfigurationNamingContext

    Returns one object per display specifier.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection] $Connection,

        [Parameter(Mandatory)]
        [string] $ConfigurationNamingContext
    )

    $entries = @(Invoke-MtLdapSearch -Connection $Connection `
            -SearchBase "CN=DisplaySpecifiers,$ConfigurationNamingContext" -Scope Subtree `
            -Filter '(objectClass=displaySpecifier)' `
            -Attributes @('name', 'adminContextMenu', 'shellContextMenu'))
    foreach ($entry in $entries) {
        [PSCustomObject]@{
            DistinguishedName = [string]$entry.DistinguishedName
            Name              = [string]$entry.name
            AdminContextMenu  = [string[]]@($entry.adminContextMenu | Where-Object { $null -ne $_ })
            ShellContextMenu  = [string[]]@($entry.shellContextMenu | Where-Object { $null -ne $_ })
        }
    }
}
