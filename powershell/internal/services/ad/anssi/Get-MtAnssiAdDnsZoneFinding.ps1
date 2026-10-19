function Get-MtAnssiAdDnsZoneFinding {
    <#
    .SYNOPSIS
    Lists the DNS zones that accept nonsecure dynamic updates, with their ANSSI level.

    .DESCRIPTION
    Returns the zones whose dynamic update setting (Get-MtAnssiAdDnsZoneAllowUpdate) is 1,
    nonsecure and secure updates. The zone of the domain itself and the _msdcs zone of the forest
    are level 1; every other zone is level 3. Zones whose name starts with two dots (deleted zones
    kept by the DNS server, trust anchors) are left out. Rows are sorted by level, then name.

    .PARAMETER Zone
    The zones, as returned by Get-MtLdapDnsZone.

    .PARAMETER DnsRoot
    The DNS name of the domain.

    .PARAMETER Forest
    The DNS name of the forest root domain.

    .EXAMPLE
    Get-MtAnssiAdDnsZoneFinding -Zone $zones -DnsRoot 'contoso.com' -Forest 'contoso.com'

    Returns rows with Name, DistinguishedName and Level.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Zone,

        [Parameter(Mandatory)]
        [string] $DnsRoot,

        [Parameter(Mandatory)]
        [string] $Forest
    )

    $critical = @($DnsRoot, "_msdcs.$Forest")
    $rows = foreach ($item in $Zone) {
        $name = [string]$item.Name
        if ($name.StartsWith('..')) { continue }
        if ((Get-MtAnssiAdDnsZoneAllowUpdate -Property $item.Property) -ne 1) { continue }
        $level = 3
        if ($name -in $critical) { $level = 1 }
        [PSCustomObject]@{
            Name = $name
            DistinguishedName = $item.DistinguishedName
            Level = $level
        }
    }
    return @($rows | Sort-Object -Property Level, Name)
}
