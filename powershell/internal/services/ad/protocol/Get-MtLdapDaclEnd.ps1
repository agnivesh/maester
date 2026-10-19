function Get-MtLdapDaclEnd {
    <#
    .SYNOPSIS
    Returns the position just after the DACL of a binary security descriptor.

    .DESCRIPTION
    Reads the size announced in the ACL header at the given offset (revision, padding, size, entry
    count, padding) and checks that the header and the size both lie inside the descriptor. The
    entries of the DACL must end before the returned position. Throws when the header does not
    fit, or when the announced size is below the size of the header or reaches past the
    descriptor.

    .PARAMETER Descriptor
    The bytes of the security descriptor.

    .PARAMETER Offset
    The position of the ACL header in the descriptor.

    .EXAMPLE
    Get-MtLdapDaclEnd -Descriptor $bytes -Offset 40

    Returns the position at which the DACL that starts at 40 ends.
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Descriptor,

        [Parameter(Mandatory)]
        [long] $Offset
    )

    if ($Offset + 8 -gt $Descriptor.Length) {
        throw "The DACL at position $Offset does not fit in the security descriptor."
    }
    $size = [BitConverter]::ToUInt16($Descriptor, $Offset + 2)
    if ($size -lt 8 -or $Offset + $size -gt $Descriptor.Length) {
        throw ("The DACL at position $Offset has a size of $size that does not fit in the " +
            'security descriptor.')
    }

    return $Offset + $size
}
