function Get-MtAnssiAdDnRelative {
    <#
    .SYNOPSIS
    Returns a distinguished name without the suffix of the domain that holds the object.

    .DESCRIPTION
    A result table that has a Domain column does not need the DC= components of the domain in
    every distinguished name. The suffix is removed only when it is the domain of the name as
    Get-MtAnssiAdDnDomain reads it, so the name of a DNS partition (DC=DomainDnsZones) stays. A name
    that is the domain itself, or has no DC= component, is returned unchanged.

    .PARAMETER DistinguishedName
    The distinguished name of the object.

    .EXAMPLE
    Get-MtAnssiAdDnRelative -DistinguishedName 'CN=Users,DC=north,DC=corp,DC=com'

    Returns CN=Users.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $DistinguishedName
    )

    $domain = Get-MtAnssiAdDnDomain -DistinguishedName $DistinguishedName
    $suffix = ',' + (($domain -split '\.' | ForEach-Object { "DC=$_" }) -join ',')
    if ($DistinguishedName.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
        return $DistinguishedName.Substring(0, $DistinguishedName.Length - $suffix.Length)
    }

    return $DistinguishedName
}
