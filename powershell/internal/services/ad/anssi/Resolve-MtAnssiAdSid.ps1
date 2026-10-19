function Resolve-MtAnssiAdSid {
    <#
    .SYNOPSIS
    Finds the SID and name behind each distinguished name of a list.

    .DESCRIPTION
    Looks each distinguished name up in a lookup built by Get-MtAnssiAdSidByDn. A foreign
    security principal (CN=<SID>,CN=ForeignSecurityPrincipals,...) carries its SID in its name
    and is resolved without the lookup. A name found in neither way gets no SID: it is outside
    the collected data, for example in another domain.

    Each result also carries the RID, the last number of the SID.

    .PARAMETER DistinguishedName
    The distinguished names to resolve.

    .PARAMETER Lookup
    The lookup returned by Get-MtAnssiAdSidByDn.

    .EXAMPLE
    Resolve-MtAnssiAdSid -DistinguishedName $rodc.RevealOnDemandGroup -Lookup $lookup

    Returns one object per name with DistinguishedName, Name, Sid and Rid.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [string[]] $DistinguishedName,

        [Parameter(Mandatory)]
        [hashtable] $Lookup
    )

    $resolved = [System.Collections.Generic.List[object]]::new()
    foreach ($dn in $DistinguishedName) {
        $sid = $null
        $name = $dn
        $entry = $Lookup[$dn]
        if ($null -ne $entry) {
            $sid = $entry.Sid
            $name = $entry.Name
        } elseif ($dn -imatch '^CN=(S-1-[0-9-]+),CN=ForeignSecurityPrincipals,') {
            $sid = $Matches[1]
            $name = $sid
        }

        $rid = $null
        if ($sid) {
            $rid = [long]($sid -split '-')[-1]
        }
        $resolved.Add([PSCustomObject]@{
                DistinguishedName = $dn
                Name              = $name
                Sid               = $sid
                Rid               = $rid
            })
    }

    return $resolved.ToArray()
}
