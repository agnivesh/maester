function Get-MtAnssiAdScannedDomain {
    <#
    .SYNOPSIS
    Returns the DNS name of the domain the scanner is connected to, or $null when unknown.

    .DESCRIPTION
    Reads the cached Domain category. The name is only used to label rows of a result table, so a
    failed read returns $null instead of failing the test.

    .EXAMPLE
    Get-MtAnssiAdScannedDomain

    Returns for example contoso.com.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        $adState = Get-MtADDomainState -Categories @('Domain')
        return [string]$adState.Domain.DnsRoot
    } catch {
        Write-Verbose "The scanned domain is unknown: $($_.Exception.Message)"
        return $null
    }
}
