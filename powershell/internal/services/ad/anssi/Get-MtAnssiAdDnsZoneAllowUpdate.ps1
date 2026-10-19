function Get-MtAnssiAdDnsZoneAllowUpdate {
    <#
    .SYNOPSIS
    Returns the dynamic update setting stored in the dNSProperty values of a DNS zone.

    .DESCRIPTION
    Each dNSProperty value holds a DataLength, NameLength, Flag, Version and Id (four bytes each,
    little-endian) followed by the data (Microsoft Learn, MS-DNSP 2.3.2.1). Returns the first data
    byte of the DSPROPERTY_ZONE_ALLOW_UPDATE property (Id 2): 0 for no dynamic update, 1 for
    nonsecure and secure updates (ZONE_UPDATE_UNSECURE), 2 for secure updates only. Returns $null
    when the zone has no such property, or when the property holds no data (the server then uses
    its default). Values shorter than the header are ignored.

    .PARAMETER Property
    The raw dNSProperty values of the zone.

    .EXAMPLE
    Get-MtAnssiAdDnsZoneAllowUpdate -Property $zone.Property

    Returns 1 for a zone that accepts nonsecure dynamic updates.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Property
    )

    foreach ($value in $Property) {
        $bytes = [byte[]]$value
        if ($bytes.Length -lt 21 -or [BitConverter]::ToUInt32($bytes, 16) -ne 2) {
            continue
        }
        if ([BitConverter]::ToUInt32($bytes, 0) -eq 0) {
            return $null
        }
        return [int]$bytes[20]
    }
    return $null
}
