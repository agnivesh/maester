function Get-MtAnssiAdDnDomain {
    <#
    .SYNOPSIS
    Returns the DNS name of the domain that holds an object, read from its distinguished name.

    .DESCRIPTION
    Takes the DC= components at the end of the distinguished name, which are the naming context of
    the object, and joins them with dots. A DC= component earlier in the name belongs to an object
    (a DNS zone, for example) and is ignored, and so is a comma escaped with a backslash. The
    DomainDnsZones and ForestDnsZones partitions are named by a first label that is not part of the
    domain name, so that label is dropped. Returns an empty string when the name has no DC=
    component.

    .PARAMETER DistinguishedName
    The distinguished name of the object.

    .EXAMPLE
    Get-MtAnssiAdDnDomain -DistinguishedName 'CN=Bob,OU=Staff,DC=north,DC=contoso,DC=com'

    Returns north.contoso.com.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $DistinguishedName
    )

    $match = [regex]::Match($DistinguishedName, '(?i)(?:^|(?<!\\),)((?:DC=[^,]+,)*DC=[^,]+)$')
    $labels = @($match.Groups[1].Value -split ',' | Where-Object { $_ } |
            ForEach-Object { $_ -replace '(?i)^DC=', '' })

    if ($labels.Count -gt 1 -and $labels[0] -match '(?i)^(Domain|Forest)DnsZones$') {
        $labels = @($labels | Select-Object -Skip 1)
    }

    return $labels -join '.'
}
