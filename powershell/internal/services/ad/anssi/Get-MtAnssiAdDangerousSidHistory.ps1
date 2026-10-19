function Get-MtAnssiAdDangerousSidHistory {
    <#
    .SYNOPSIS
    Finds the SID history values that are well-known or privileged SIDs.

    .DESCRIPTION
    Checks every SID of every object with Get-MtAnssiAdSidRisk and returns one object for each SID
    that is not the SID of an ordinary migrated account or group.

    .PARAMETER Object
    The objects with a SID history, as returned by Get-MtAnssiAdSidHistoryObject.

    .EXAMPLE
    Get-MtAnssiAdDangerousSidHistory -Object $objects

    Returns one object with Type, Name, Sid, Risk and LastLogonDate for each dangerous SID.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Object
    )

    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Object) {
        foreach ($sid in $item.SidHistory) {
            $risk = Get-MtAnssiAdSidRisk -Sid $sid
            if ($null -eq $risk) { continue }

            $found.Add([PSCustomObject]@{
                    Type          = $item.Type
                    Name          = $item.Name
                    Sid           = $sid
                    Risk          = $risk
                    LastLogonDate = $item.LastLogonDate
                })
        }
    }

    return $found.ToArray()
}
