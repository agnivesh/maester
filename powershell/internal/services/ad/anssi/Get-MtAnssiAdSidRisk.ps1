function Get-MtAnssiAdSidRisk {
    <#
    .SYNOPSIS
    Tells whether a SID has no place in a SID history.

    .DESCRIPTION
    A SID history is filled by a domain migration with the SIDs of the migrated accounts and
    groups. Two kinds of SID are never legitimate there:

    - WellKnown: a SID outside the domain SIDs of the form S-1-5-21-a-b-c-rid, for example Everyone
      (S-1-1-0), SYSTEM (S-1-5-18) or the built-in Administrators group (S-1-5-32-544). Well-known
      SIDs are the same in every domain and cannot be migrated.
    - PrivilegedDomain: a domain SID whose relative identifier is below 1000, the range of the
      accounts and groups that Windows creates itself: Administrator (500), krbtgt (502), Domain
      Admins (512), Schema Admins (518), Enterprise Admins (519) and the others.

    Returns null for the SID of an ordinary account or group (a relative identifier of 1000 or
    more), for a domain SID without a relative identifier and for text that is not a SID.

    .PARAMETER Sid
    The SID in its string form, for example S-1-5-21-1-2-3-512.

    .EXAMPLE
    Get-MtAnssiAdSidRisk -Sid 'S-1-5-21-1-2-3-519'

    Returns PrivilegedDomain.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Sid
    )

    $domainRelativePrefix = '^S-1-5-21(-\d+){3}'
    $privilegedRidLimit = 1000

    if ($Sid -match "$domainRelativePrefix-(\d+)$") {
        if ([long]$Matches[2] -lt $privilegedRidLimit) { return 'PrivilegedDomain' }
        return $null
    }
    if ($Sid -match '^S-1-5-21(-\d+)*$') { return $null }
    if ($Sid -match '^S-1-\d+(-\d+)*$') { return 'WellKnown' }

    return $null
}
