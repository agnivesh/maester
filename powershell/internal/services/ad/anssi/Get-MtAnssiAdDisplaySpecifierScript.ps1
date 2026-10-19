function Get-MtAnssiAdDisplaySpecifierScript {
    <#
    .SYNOPSIS
    Lists the context menu entries of display specifiers that run a program from a file share.

    .DESCRIPTION
    A context menu value has the form <order>,<menu text>,<command>. Returns one object per
    value whose command is a UNC path (\\server\share\...), with Specifier (the display
    specifier name and its locale), Attribute, Command and Location: 'SYSVOL' when the share is
    SYSVOL or NETLOGON, 'File server' otherwise. Commands that are COM class IDs or local paths
    are left out.

    .PARAMETER DisplaySpecifier
    The display specifiers, as returned by Get-MtLdapDisplaySpecifier.

    .EXAMPLE
    Get-MtAnssiAdDisplaySpecifierScript -DisplaySpecifier $specifiers

    Returns the entries that run a program from a file share.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $DisplaySpecifier
    )

    foreach ($specifier in $DisplaySpecifier) {
        $locale = ''
        $dn = [string]$specifier.DistinguishedName
        if ($dn -match ',CN=([0-9A-Fa-f]+),CN=DisplaySpecifiers,') {
            $locale = " ($($Matches[1]))"
        }
        $values = @($specifier.AdminContextMenu | ForEach-Object { , @('adminContextMenu', $_) }) +
            @($specifier.ShellContextMenu | ForEach-Object { , @('shellContextMenu', $_) })
        foreach ($pair in $values) {
            $command = (([string]$pair[1]) -split ',', 3)[-1].Trim()
            if ($command -notmatch '^\\\\[^\\]+\\([^\\]+)') {
                continue
            }
            $location = 'File server'
            if ($Matches[1] -in 'SYSVOL', 'NETLOGON') {
                $location = 'SYSVOL'
            }
            [PSCustomObject]@{
                Specifier = "$($specifier.Name)$locale"
                Attribute = $pair[0]
                Command   = $command
                Location  = $location
            }
        }
    }
}
