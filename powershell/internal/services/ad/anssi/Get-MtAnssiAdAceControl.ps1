function Get-MtAnssiAdAceControl {
    <#
    .SYNOPSIS
    Lists the dangerous rights that untrusted principals hold on directory objects.

    .DESCRIPTION
    For each object read by Get-MtLdapObjectSecurity, returns an Owner row (level 1) when the
    owner is not trusted, since an owner can always rewrite the DACL, then one row per DACL entry
    that grants a right of Get-MtAnssiAdAceRule to an untrusted principal (see
    Get-MtAnssiAdObjectAceControl). Trust is decided once per distinct SID by
    Select-MtAnssiAdUntrustedSid. Each row has DistinguishedName, Name, Sid, Control, Level and
    IsInherited.

    Throws for an object whose DACL was not read (Ace $null): the caller decides what an
    unreadable object means before asking for its rights.

    .PARAMETER Object
    The objects, as returned by Get-MtLdapObjectSecurity.

    .PARAMETER TrustedSid
    The SIDs whose rights are expected, for example from Get-MtAnssiAdTrustedSid.

    .PARAMETER Rule
    The rights to look for, in the form of the rows of Get-MtAnssiAdAceRule. Without it, or with
    an empty list, the rows of Get-MtAnssiAdAceRule are used. The owner check does not depend on it.

    .EXAMPLE
    Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted

    Returns the dangerous rights held by untrusted principals on the objects.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Object,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]] $TrustedSid,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Rule
    )

    $rule = @($Rule | Where-Object { $null -ne $_ })
    if ($rule.Count -eq 0) { $rule = @(Get-MtAnssiAdAceRule) }
    $ruleBit = [uint32]0
    $rule | Where-Object { ($_.Mask -band ($_.Mask - 1)) -eq 0 } |
        ForEach-Object { $ruleBit = $ruleBit -bor $_.Mask }

    $allSid = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Object) {
        if ($null -eq $item.Ace) {
            throw "The DACL of '$($item.DistinguishedName)' was not read: its rights are unknown."
        }
        $null = $allSid.Add([string]$item.OwnerSid)
        foreach ($ace in $item.Ace) { $null = $allSid.Add([string]$ace.Sid) }
    }
    $untrusted = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(Select-MtAnssiAdUntrustedSid -Sid @($allSid) -TrustedSid $TrustedSid),
        [System.StringComparer]::OrdinalIgnoreCase)

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Object) {
        if ($untrusted.Contains([string]$item.OwnerSid)) {
            $rows.Add([PSCustomObject]@{
                    DistinguishedName = $item.DistinguishedName
                    Name              = $item.Name
                    Sid               = [string]$item.OwnerSid
                    Control           = 'Owner'
                    Level             = 1
                    IsInherited       = $false
                })
        }
        foreach ($found in @(Get-MtAnssiAdObjectAceControl -Object $item -UntrustedSid $untrusted `
                    -Rule $rule -RuleBit $ruleBit)) {
            $rows.Add($found)
        }
    }
    return $rows.ToArray()
}
