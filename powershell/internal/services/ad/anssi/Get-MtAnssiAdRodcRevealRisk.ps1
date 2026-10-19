function Get-MtAnssiAdRodcRevealRisk {
    <#
    .SYNOPSIS
    Finds the privileged entries in the reveal list of read-only domain controllers.

    .DESCRIPTION
    The msDS-RevealOnDemandGroup list of a read-only domain controller (RODC) names the accounts
    whose secrets it may cache. An entry whose RID is lower than 1000 is a built-in, usually
    privileged, account or group and should not be there. The Allowed RODC Password Replication
    Group (domain RID 571) is the default entry of the list and is accepted; its members are
    checked by ANSSI-AD-067.

    Returns one object per RODC with the risky entries and the number of entries that could not
    be resolved to a SID, because they are outside the collected data.

    .PARAMETER Controller
    The read-only domain controllers, as returned by Get-MtAnssiAdDomainController.

    .PARAMETER Lookup
    The lookup returned by Get-MtAnssiAdSidByDn.

    .PARAMETER DomainSid
    The SID of the domain.

    .EXAMPLE
    Get-MtAnssiAdRodcRevealRisk -Controller $rodcs -Lookup $lookup -DomainSid $domainSid

    Returns each RODC with its Risky entries and its Unresolved count.
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

    $allowedGroup = "$DomainSid-571"
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Controller) {
        $entries = @(Resolve-MtAnssiAdSid -DistinguishedName $item.Computer.RevealOnDemandGroup `
                -Lookup $Lookup)
        $risky = @($entries | Where-Object {
                $null -ne $_.Rid -and $_.Rid -lt 1000 -and $_.Sid -ne $allowedGroup
            } | ForEach-Object { "$($_.Name) ($($_.Sid))" })
        $rows.Add([PSCustomObject]@{
                Name              = $item.Computer.Name
                DistinguishedName = $item.Computer.DistinguishedName
                Risky             = $risky
                Unresolved        = @($entries | Where-Object { $null -eq $_.Sid }).Count
            })
    }

    return $rows.ToArray()
}
