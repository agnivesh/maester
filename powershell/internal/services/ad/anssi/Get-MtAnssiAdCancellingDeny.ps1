function Get-MtAnssiAdCancellingDeny {
    <#
    .SYNOPSIS
    Returns the first earlier deny entry that takes a right away from an allow entry.

    .DESCRIPTION
    A deny entry cancels the right when it is for the same trustee as the allow entry, for
    Everyone (S-1-1-0) or for Authenticated Users (S-1-5-11), when its mask covers every bit of
    the right, and when its object type is empty or the same as the allow entry's. Returns that
    deny entry, or nothing. Deny entries for other groups are not considered.

    .PARAMETER Ace
    The allow entry.

    .PARAMETER Deny
    The deny entries that come before it in the DACL and apply to the object.

    .PARAMETER Bit
    The access mask bits of the right.

    .EXAMPLE
    Get-MtAnssiAdCancellingDeny -Ace $ace -Deny $deny -Bit 0x40000

    Returns a deny of WRITE_DAC for Everyone placed before the allow entry, if there is one.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [object] $Ace,

        [AllowEmptyCollection()]
        [object[]] $Deny = @(),

        [Parameter(Mandatory)]
        [uint32] $Bit
    )

    $denySid = @($Ace.Sid, 'S-1-1-0', 'S-1-5-11')
    foreach ($entry in $Deny) {
        $sameType = $entry.ObjectType -in @('', $Ace.ObjectType)
        if ($entry.Sid -in $denySid -and $sameType -and ($entry.Mask -band $Bit) -eq $Bit) {
            return $entry
        }
    }
}
