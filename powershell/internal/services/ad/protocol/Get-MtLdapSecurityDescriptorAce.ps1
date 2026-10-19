function Get-MtLdapSecurityDescriptorAce {
    <#
    .SYNOPSIS
    Returns the entries of the DACL of a binary security descriptor.

    .DESCRIPTION
    Walks the discretionary access control list (DACL) of a self-relative security descriptor,
    as stored in Active Directory, and returns one object per entry, in order: its position,
    Type (Allow, Deny or Other), raw AceType, access Mask, ObjectType and InheritedObjectType
    (GUID text, empty when absent), the InheritOnly and IsInherited flags, and the trustee Sid.
    Allow and Deny cover the basic and object entry types (0, 1, 5, 6); any other type is
    returned as Other with no Sid. A descriptor without a DACL gives nothing.

    The bytes are read directly, so this works on every platform, unlike the .NET access control
    classes, which are not supported outside Windows. Throws when the descriptor is malformed:
    the DACL must lie inside the descriptor with the size its header announces, and every entry
    inside the DACL.

    .PARAMETER Descriptor
    The bytes of the security descriptor.

    .EXAMPLE
    Get-MtLdapSecurityDescriptorAce -Descriptor $bytes

    Returns the entries of the DACL.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Descriptor
    )

    if ($Descriptor.Length -lt 20) {
        throw "The security descriptor has $($Descriptor.Length) bytes, fewer than its header."
    }
    $daclOffset = [BitConverter]::ToUInt32($Descriptor, 16)
    $entries = [System.Collections.Generic.List[object]]::new()
    if ($daclOffset -eq 0) {
        return $entries.ToArray()
    }
    $daclEnd = Get-MtLdapDaclEnd -Descriptor $Descriptor -Offset $daclOffset

    $aceCount = [BitConverter]::ToUInt16($Descriptor, $daclOffset + 4)
    $position = $daclOffset + 8
    for ($index = 0; $index -lt $aceCount; $index++) {
        if ($position + 8 -gt $daclEnd) {
            throw "Entry $index of the DACL does not fit in the DACL."
        }
        $size = [int][BitConverter]::ToUInt16($Descriptor, $position + 2)
        if ($size -lt 8 -or $position + $size -gt $daclEnd) {
            throw "Entry $index of the DACL has a size of $size that does not fit."
        }
        $entry = ConvertFrom-MtLdapBinaryAce -Bytes $Descriptor -Offset $position -Index $index
        $entries.Add($entry)
        $position += $size
    }

    return $entries.ToArray()
}
