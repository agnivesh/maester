function Get-MtAnssiAdDcResourceDelegation {
    <#
    .SYNOPSIS
    Finds the domain controllers on which resource-based constrained delegation is configured.

    .DESCRIPTION
    Resource-based constrained delegation is configured on the target account, in its
    msDS-AllowedToActOnBehalfOfOtherIdentity attribute. Returns one object for each domain
    controller that has the attribute, whatever it allows, with the accounts it allows: their name
    when they are in the collected data, their SID otherwise. A descriptor that could not be read
    gives a controller without allowed accounts; it is still returned, since the attribute is set.

    .PARAMETER Controller
    The domain controllers, as returned by Get-MtAnssiAdDomainController, with
    AllowedToActOnBehalfOfOtherIdentity on their computer accounts.

    .PARAMETER Lookup
    The lookup returned by Get-MtAnssiAdSidByDn, used to name the allowed accounts.

    .EXAMPLE
    Get-MtAnssiAdDcResourceDelegation -Controller $controllers -Lookup $lookup

    Returns the domain controllers with resource-based delegation and the accounts it allows.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object[]] $Controller,

        [Parameter(Mandatory)]
        [hashtable] $Lookup
    )

    $nameBySid = @{}
    foreach ($entry in $Lookup.Values) {
        $nameBySid[$entry.Sid] = $entry.Name
    }

    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Controller) {
        $allowed = $item.Computer.AllowedToActOnBehalfOfOtherIdentity
        if ($null -eq $allowed) {
            continue
        }

        $names = foreach ($sid in $allowed) {
            if ($nameBySid.ContainsKey($sid)) { "$($nameBySid[$sid]) ($sid)" } else { $sid }
        }
        $found.Add([PSCustomObject]@{
                Name              = $item.Computer.Name
                DistinguishedName = $item.Computer.DistinguishedName
                Type              = $item.Type
                Allowed           = @($names)
            })
    }

    return $found.ToArray()
}
