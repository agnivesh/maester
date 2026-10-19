function Get-MtAnssiAdRodcNeverRevealGap {
    <#
    .SYNOPSIS
    Finds the read-only domain controllers whose never-reveal list lacks a required group.

    .DESCRIPTION
    The msDS-NeverRevealGroup list of a read-only domain controller (RODC) names the accounts
    whose secrets it must never cache. It should name at least Administrators (S-1-5-32-544),
    Server Operators (S-1-5-32-549), Account Operators (S-1-5-32-548), Backup Operators
    (S-1-5-32-551) and the Denied RODC Password Replication Group (domain RID 572). Only direct
    entries count. Returns one object per RODC that lacks at least one of them.

    .PARAMETER Controller
    The read-only domain controllers, as returned by Get-MtAnssiAdDomainController.

    .PARAMETER Lookup
    The lookup returned by Get-MtAnssiAdSidByDn.

    .PARAMETER DomainSid
    The SID of the domain.

    .EXAMPLE
    Get-MtAnssiAdRodcNeverRevealGap -Controller $rodcs -Lookup $lookup -DomainSid $domainSid

    Returns the RODCs with the names of the groups missing from their list.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object[]] $Controller,

        [Parameter(Mandatory)]
        [hashtable] $Lookup,

        [Parameter(Mandatory)]
        [string] $DomainSid
    )

    $required = @(
        @{ Sid = 'S-1-5-32-544'; Name = 'Administrators' }
        @{ Sid = 'S-1-5-32-549'; Name = 'Server Operators' }
        @{ Sid = 'S-1-5-32-548'; Name = 'Account Operators' }
        @{ Sid = 'S-1-5-32-551'; Name = 'Backup Operators' }
        @{ Sid = "$DomainSid-572"; Name = 'Denied RODC Password Replication Group' }
    )

    $gaps = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Controller) {
        $present = @(Resolve-MtAnssiAdSid -DistinguishedName $item.Computer.NeverRevealGroup `
                -Lookup $Lookup | ForEach-Object { $_.Sid })
        $missing = @($required | Where-Object { $present -notcontains $_.Sid } |
                ForEach-Object { $_.Name })
        if ($missing.Count -gt 0) {
            $gaps.Add([PSCustomObject]@{
                    Name              = $item.Computer.Name
                    DistinguishedName = $item.Computer.DistinguishedName
                    Missing           = $missing
                })
        }
    }

    return $gaps.ToArray()
}
