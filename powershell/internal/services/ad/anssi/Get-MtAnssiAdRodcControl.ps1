function Get-MtAnssiAdRodcControl {
    <#
    .SYNOPSIS
    Adds the read-only domain controller rules to the dangerous rights found on controllers.

    .DESCRIPTION
    The principal named in the managedBy attribute of a read-only domain controller (RODC) is a
    local administrator of it, so it can read the secrets the RODC caches. The rights found by
    Get-MtAnssiAdAceControl are returned with the right to write managedBy raised to level 1 on
    RODCs, followed by a level 1 ManagedBy row for each RODC with a manager that is not trusted. A
    manager that is not in the collected data is shown by its distinguished name and is not
    trusted.

    .PARAMETER Controller
    The domain controllers, as returned by Get-MtAnssiAdDomainController.

    .PARAMETER Row
    The rows of Get-MtAnssiAdAceControl for the controller objects.

    .PARAMETER Lookup
    The distinguished name lookup of Get-MtAnssiAdSidByDn.

    .PARAMETER TrustedSid
    The SIDs whose rights are expected.

    .EXAMPLE
    Get-MtAnssiAdRodcControl -Controller $controllers -Row $rows -Lookup $lookup `
        -TrustedSid $trusted

    Returns the rows with the RODC rules applied.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Controller,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Row,

        [Parameter(Mandatory)]
        [hashtable] $Lookup,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]] $TrustedSid
    )

    $rodc = @($Controller | Where-Object { $_.Type -eq 'ReadOnly' })
    $rodcDn = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($rodc.Computer.DistinguishedName), [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Row) {
        $onRodc = $rodcDn.Contains([string]$entry.DistinguishedName)
        if ($entry.Control -eq 'WriteManagedBy' -and $onRodc) {
            $entry = $entry.PSObject.Copy()
            $entry.Level = 1
        }
        $entry
    }

    foreach ($item in $rodc) {
        $manager = [string]$item.Computer.ManagedBy
        $sid = $manager
        if ($Lookup.ContainsKey($manager)) { $sid = $Lookup[$manager].Sid }
        if (@(Select-MtAnssiAdUntrustedSid -Sid $sid -TrustedSid $TrustedSid).Count -gt 0) {
            [PSCustomObject]@{
                DistinguishedName = [string]$item.Computer.DistinguishedName
                Name              = [string]$item.Computer.Name
                Sid               = $sid
                Control           = 'ManagedBy'
                Level             = 1
                IsInherited       = $false
            }
        }
    }
}
