function Get-MtAnssiAdKeyAdminsBroadAce {
    <#
    .SYNOPSIS
    Returns the entries that give the Key Admins or Enterprise Key Admins group more than it needs.

    .DESCRIPTION
    Since Windows Server 2016 the domain preparation grants the Key Admins (RID 526) and
    Enterprise Key Admins (RID 527) groups read and write access to the msDS-KeyCredentialLink
    attribute on the domain root, and nothing else. Revision 15 of the preparation set far wider
    entries (ANSSI finding vuln_adupdate_bad). Only Allow entries for the built-in RIDs 526 and 527
    of a domain are looked at, and one is returned when Get-MtAnssiAdKeyAdminsAceIsBroad says it
    is broad. An entry that only inherits still counts, because it reaches the objects below.

    .PARAMETER Ace
    The DACL entries of the domain root, as returned by Get-MtAnssiAdObjectSecurity.

    .EXAMPLE
    Get-MtAnssiAdKeyAdminsBroadAce -Ace $object.Ace

    Returns one object per broad entry with Group, Sid, Mask (hex text) and ObjectType.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Ace
    )

    $groupByRid = @{ '526' = 'Key Admins'; '527' = 'Enterprise Key Admins' }

    foreach ($entry in @($Ace | Where-Object { $null -ne $_ })) {
        $sid = [string]$entry.Sid
        if ($entry.Type -ne 'Allow' -or $sid -notmatch '^S-1-5-21-\d+-\d+-\d+-(52[67])$') {
            continue
        }
        if (-not (Get-MtAnssiAdKeyAdminsAceIsBroad -Ace $entry)) {
            continue
        }

        $objectType = [string]$entry.ObjectType
        if (-not $objectType) { $objectType = 'all' }
        [PSCustomObject]@{
            Group      = $groupByRid[$Matches[1]]
            Sid        = $sid
            Mask       = ('0x{0:X}' -f [int64][uint32]$entry.Mask)
            ObjectType = $objectType
        }
    }
}
