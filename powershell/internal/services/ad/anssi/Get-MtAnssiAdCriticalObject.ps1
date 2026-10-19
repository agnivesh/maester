function Get-MtAnssiAdCriticalObject {
    <#
    .SYNOPSIS
    Lists the critical directory objects that are missing or whose permissions cannot be read.

    .DESCRIPTION
    The critical objects are AdminSDHolder, the built-in Administrator (RID 500) and krbtgt (RID
    502) accounts, Domain Admins (512) and, in the forest root domain, Schema Admins (518) and
    Enterprise Admins (519). An account or group that is not in the collected data is returned
    as not found. The others are read with Get-MtAnssiAdObjectSecurity, and those whose security
    descriptor does not come back are returned as not readable. Each row has Object, Distinguished
    name and Problem. Throws when a read fails, for example when AdminSDHolder cannot be read at
    all.

    .PARAMETER AdState
    The collected state, with the Domain, Users and Groups categories.

    .EXAMPLE
    Get-MtAnssiAdCriticalObject -AdState $adState

    Returns the critical objects with a problem.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $AdState
    )

    $domainSid = [string]$AdState.Domain.DomainSID.Value
    $wanted = @(@(500, 'Administrator'), @(502, 'krbtgt'), @(512, 'Domain Admins'))
    if ([string]$AdState.Domain.DnsRoot -eq [string]$AdState.Domain.Forest) {
        $wanted += @(, @(518, 'Schema Admins'))
        $wanted += @(, @(519, 'Enterprise Admins'))
    }
    $bySid = @{}
    foreach ($item in @($AdState.Users) + @($AdState.Groups)) {
        $bySid[[string]$item.Sid.Value] = $item
    }

    $target = [ordered]@{}
    $target["CN=AdminSDHolder,CN=System,$($AdState.Domain.DistinguishedName)"] = 'AdminSDHolder'
    foreach ($pair in $wanted) {
        $item = $bySid["$domainSid-$($pair[0])"]
        $label = "$($pair[1]) (RID $($pair[0]))"
        if ($null -eq $item) {
            [PSCustomObject]@{
                Object = $label; DistinguishedName = ''; Problem = 'Not found in the collected data'
            }
        } else {
            $target[[string]$item.DistinguishedName] = $label
        }
    }

    $objects = @(Get-MtAnssiAdObjectSecurity -DistinguishedName @($target.Keys) `
            -ProtocolEvidence $AdState.ProtocolEvidence)
    foreach ($object in $objects) {
        if ($null -eq $object.Ace) {
            [PSCustomObject]@{
                Object            = $target[$object.DistinguishedName]
                DistinguishedName = $object.DistinguishedName
                Problem           = 'Permissions not readable'
            }
        }
    }
}
