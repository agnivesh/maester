function ConvertFrom-MtLdapBinarySid {
    <#
    .SYNOPSIS
    Reads a binary SID at a position of a byte array and returns it as text.

    .DESCRIPTION
    A binary SID holds a revision byte, a count of sub-authorities, a six-byte identifier
    authority (big-endian) and the sub-authorities (four bytes each, little-endian). This works
    on every platform, unlike System.Security.Principal.SecurityIdentifier outside Windows.

    Throws when the SID does not fit in the array.

    .PARAMETER Bytes
    The bytes that hold the SID.

    .PARAMETER Offset
    The position of the SID in the bytes.

    .EXAMPLE
    ConvertFrom-MtLdapBinarySid -Bytes $bytes -Offset 20

    Returns a SID such as S-1-5-21-1-2-3-1105.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [int] $Offset
    )

    if ($Offset -lt 0) {
        throw "The SID at position $Offset does not fit in $($Bytes.Length) bytes."
    }
    $count = [int]$Bytes[$Offset + 1]
    if ($Offset + 8 + 4 * $count -gt $Bytes.Length) {
        throw "The SID at position $Offset does not fit in $($Bytes.Length) bytes."
    }

    $authority = [uint64]0
    for ($index = 2; $index -lt 8; $index++) {
        $authority = ($authority -shl 8) -bor $Bytes[$Offset + $index]
    }
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add('S')
    $parts.Add([string]$Bytes[$Offset])
    $parts.Add([string]$authority)
    for ($index = 0; $index -lt $count; $index++) {
        $parts.Add([string][BitConverter]::ToUInt32($Bytes, $Offset + 8 + 4 * $index))
    }

    return ($parts -join '-')
}
