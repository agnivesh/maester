function Get-MtAnssiAdKeyAdminsAssessment {
    <#
    .SYNOPSIS
    Reads the domain root and reports whether the Key Admins groups hold a broad right on it.

    .DESCRIPTION
    Reads the owner and DACL of the domain root once per session (Get-MtAnssiAdObjectSecurity) and
    passes the entries to Get-MtAnssiAdKeyAdminsBroadAce. Readable is $false when there is no
    protocol evidence, no distinguished name for the domain, or the server returned no descriptor:
    the caller skips instead of passing on nothing. A failed read throws.

    .PARAMETER AdState
    The state returned by Get-MtADDomainState, with Domain.DistinguishedName and ProtocolEvidence.

    .EXAMPLE
    Get-MtAnssiAdKeyAdminsAssessment -AdState $adState

    Returns an object with Readable (bool) and Broad (the broad entries).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object] $AdState
    )

    $domainDn = [string]$AdState.Domain.DistinguishedName
    if (-not $AdState.ProtocolEvidence -or -not $domainDn) {
        return [PSCustomObject]@{ Readable = $false; Broad = @() }
    }

    $root = @(Get-MtAnssiAdObjectSecurity -ProtocolEvidence $AdState.ProtocolEvidence `
            -DistinguishedName $domainDn)[0]
    if ($null -eq $root.Ace) {
        return [PSCustomObject]@{ Readable = $false; Broad = @() }
    }

    return [PSCustomObject]@{
        Readable = $true
        Broad    = @(Get-MtAnssiAdKeyAdminsBroadAce -Ace $root.Ace)
    }
}
