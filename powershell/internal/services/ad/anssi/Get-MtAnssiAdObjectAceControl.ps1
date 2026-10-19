function Get-MtAnssiAdObjectAceControl {
    <#
    .SYNOPSIS
    Lists the dangerous rights that the DACL of one object grants to untrusted principals.

    .DESCRIPTION
    Goes through the DACL entries in order. Inherit-only entries are skipped: they do not apply to
    the object itself (Active Directory also marks an inherited entry meant for another class as
    inherit-only). Deny entries are kept for the allow entries that follow them. An allow entry
    whose mask holds none of the rule bits, or whose trustee is trusted, is skipped; for the
    others, Select-MtAnssiAdAceControl picks the right, if any. Returns one row per entry with a
    right: DistinguishedName, Name, Sid, Control, Level and IsInherited.

    .PARAMETER Object
    One object, as returned by Get-MtLdapObjectSecurity, with its DACL read.

    .PARAMETER UntrustedSid
    The SIDs that are not trusted, from Select-MtAnssiAdUntrustedSid.

    .PARAMETER Rule
    The rows of Get-MtAnssiAdAceRule.

    .PARAMETER RuleBit
    The mask bits that at least one rule can match, used to skip harmless entries quickly.

    .EXAMPLE
    Get-MtAnssiAdObjectAceControl -Object $object -UntrustedSid $untrusted -Rule $rule `
        -RuleBit $bits

    Returns the dangerous rights held by untrusted principals on the object.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $Object,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]] $UntrustedSid,

        [Parameter(Mandatory)]
        [object[]] $Rule,

        [Parameter(Mandatory)]
        [uint32] $RuleBit
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $deny = [System.Collections.Generic.List[object]]::new()
    foreach ($ace in $Object.Ace) {
        if ($ace.InheritOnly) { continue }
        if ($ace.Type -eq 'Deny') { $deny.Add($ace); continue }
        if ($ace.Type -ne 'Allow' -or ($ace.Mask -band $RuleBit) -eq 0) { continue }
        if (-not $UntrustedSid.Contains([string]$ace.Sid)) { continue }
        $match = Select-MtAnssiAdAceControl -Ace $ace -Deny $deny.ToArray() -Rule $Rule `
            -ObjectClass $Object.ObjectClass
        if ($null -ne $match) {
            $rows.Add([PSCustomObject]@{
                    DistinguishedName = $Object.DistinguishedName
                    Name              = $Object.Name
                    Sid               = $ace.Sid
                    Control           = $match.Control
                    Level             = $match.Level
                    IsInherited       = $ace.IsInherited
                })
        }
    }
    return $rows.ToArray()
}
