function Select-MtAnssiAdAceControl {
    <#
    .SYNOPSIS
    Returns the first dangerous-right rule that an allow entry grants and no earlier deny cancels.

    .DESCRIPTION
    Goes through the rules of Get-MtAnssiAdAceRule in order. An entry matches a rule when its mask
    holds all of the rule's bits, its object type fits the rule ('*' takes any, '' only an entry
    without object type, a GUID only that GUID), the object type is not one the rule ignores
    (IgnoreType) and, for a rule limited to some classes, the object has one of them. A matched
    rule is cancelled when Get-MtAnssiAdCancellingDeny finds an earlier deny entry for it.
    Returns the first rule that is matched and not cancelled, or nothing. The tests are written
    inline because this runs for every candidate entry.

    .PARAMETER Ace
    The allow entry, as returned by Get-MtLdapSecurityDescriptorAce.

    .PARAMETER Deny
    The deny entries that come before it in the DACL and apply to the object.

    .PARAMETER Rule
    The rows of Get-MtAnssiAdAceRule.

    .PARAMETER ObjectClass
    Every class of the object that carries the entry.

    .EXAMPLE
    Select-MtAnssiAdAceControl -Ace $ace -Deny $deny -Rule (Get-MtAnssiAdAceRule) `
        -ObjectClass $class

    Returns the WriteDacl rule for an entry that grants WRITE_DAC with no deny in front of it.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [object] $Ace,

        [AllowEmptyCollection()]
        [object[]] $Deny = @(),

        [Parameter(Mandatory)]
        [object[]] $Rule,

        [AllowEmptyCollection()]
        [string[]] $ObjectClass = @()
    )

    foreach ($row in $Rule) {
        if (($Ace.Mask -band $row.Mask) -ne $row.Mask) { continue }
        if ($row.ObjectType -notin @('*', $Ace.ObjectType)) { continue }
        if ($Ace.ObjectType -in $row.IgnoreType) { continue }
        if ($null -ne $row.Class -and -not $row.Class.Overlaps($ObjectClass)) { continue }
        if ($null -eq (Get-MtAnssiAdCancellingDeny -Ace $Ace -Deny $Deny -Bit $row.Mask)) {
            return $row
        }
    }
}
