function Get-MtAnssiAdOwnerFinding {
    <#
    .SYNOPSIS
    Groups the objects older than 7 days that have an owner ANSSI does not expect, by owner.

    .DESCRIPTION
    ANSSI expects users, computers, groups, organizational units and GPOs to be owned by Domain
    Admins (the domain SID followed by 512), Enterprise Admins (RID 519, a group of the forest
    root domain, so any domain SID is accepted), Administrators (S-1-5-32-544) or SYSTEM
    (S-1-5-18). Objects created in the last 7 days are left out; objects without a creation date
    are checked. Returns one object per unexpected owner with OwnerSid (empty when the owner
    could not be read), ObjectCount and Example (up to 3 object names), the owners with the most
    objects first.

    .PARAMETER Object
    The objects, as returned by Get-MtLdapObjectOwner.

    .PARAMETER DomainSid
    The SID of the collected domain.

    .PARAMETER Now
    The current date, from which the 7 days are counted.

    .EXAMPLE
    Get-MtAnssiAdOwnerFinding -Object $objects -DomainSid $domainSid -Now (Get-Date)

    Returns the unexpected owners.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Object,

        [Parameter(Mandatory)]
        [string] $DomainSid,

        [Parameter(Mandatory)]
        [datetime] $Now
    )

    $cutoff = $Now.AddDays(-7)
    $allowed = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@("$DomainSid-512", 'S-1-5-32-544', 'S-1-5-18'))
    $byOwner = @{}
    foreach ($item in $Object) {
        if ($item.Created -gt $cutoff) {
            continue
        }
        $owner = [string]$item.OwnerSid
        if ($allowed.Contains($owner) -or $owner -match '^S-1-5-21-\d+-\d+-\d+-519$') {
            continue
        }
        if (-not $byOwner.ContainsKey($owner)) {
            $byOwner[$owner] = [PSCustomObject]@{
                OwnerSid    = $owner
                ObjectCount = 0
                Example     = [System.Collections.Generic.List[string]]::new()
            }
        }
        $finding = $byOwner[$owner]
        $finding.ObjectCount++
        if ($finding.Example.Count -lt 3) {
            $finding.Example.Add([string]$item.Name)
        }
    }

    $mostFirst = @{ Expression = 'ObjectCount'; Descending = $true }
    return @($byOwner.Values | Sort-Object -Property $mostFirst, OwnerSid)
}
