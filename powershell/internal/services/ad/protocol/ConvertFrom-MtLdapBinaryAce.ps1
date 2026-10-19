function ConvertFrom-MtLdapBinaryAce {
    <#
    .SYNOPSIS
    Reads one access control entry from the bytes of a security descriptor.

    .DESCRIPTION
    Reads the entry that starts at the given offset: its type, flags, access mask and, for
    object entries (types 5 and 6), the object type and inherited object type GUIDs that the
    object flags announce, then the trustee SID. Types 0 and 5 are Allow, 1 and 6 are Deny; any
    other type is returned as Other with no Sid. The caller checks that the entry size fits in
    the bytes. Throws when the SID does not fit in the entry.

    .PARAMETER Bytes
    The bytes of the security descriptor.

    .PARAMETER Offset
    The position of the entry in the bytes.

    .PARAMETER Index
    The position of the entry in the DACL, returned as Index.

    .EXAMPLE
    ConvertFrom-MtLdapBinaryAce -Bytes $descriptor -Offset 48 -Index 0

    Returns the first entry of a DACL that starts at position 40.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [int] $Offset,

        [Parameter(Mandatory)]
        [int] $Index
    )

    $aceType = $Bytes[$Offset]
    $aceFlags = $Bytes[$Offset + 1]
    $size = [int][BitConverter]::ToUInt16($Bytes, $Offset + 2)
    $type = @{ 0 = 'Allow'; 5 = 'Allow'; 1 = 'Deny'; 6 = 'Deny' }[[int]$aceType]
    if ($null -eq $type) { $type = 'Other' }

    $objectType = ''
    $inheritedObjectType = ''
    $sidOffset = $Offset + 8
    if ($aceType -in 5, 6) {
        $objectFlags = [BitConverter]::ToUInt32($Bytes, $Offset + 8)
        $sidOffset = $Offset + 12
        if ($objectFlags -band 1) {
            $guidBytes = [byte[]]$Bytes[$sidOffset..($sidOffset + 15)]
            $objectType = [guid]::new($guidBytes).ToString()
            $sidOffset += 16
        }
        if ($objectFlags -band 2) {
            $guidBytes = [byte[]]$Bytes[$sidOffset..($sidOffset + 15)]
            $inheritedObjectType = [guid]::new($guidBytes).ToString()
            $sidOffset += 16
        }
    }

    $sid = $null
    if ($type -ne 'Other') {
        if ($sidOffset + 8 -gt $Offset + $size) {
            throw "The SID of entry $Index does not fit in the entry."
        }
        $sid = ConvertFrom-MtLdapBinarySid -Bytes $Bytes -Offset $sidOffset
    }

    [PSCustomObject]@{
        Index               = $Index
        Type                = $type
        AceType             = [int]$aceType
        Mask                = [BitConverter]::ToUInt32($Bytes, $Offset + 4)
        ObjectType          = $objectType
        InheritedObjectType = $inheritedObjectType
        InheritOnly         = [bool]($aceFlags -band 0x08)
        IsInherited         = [bool]($aceFlags -band 0x10)
        Sid                 = $sid
    }
}
