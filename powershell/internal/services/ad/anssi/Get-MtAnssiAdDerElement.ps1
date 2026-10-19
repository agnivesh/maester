function Get-MtAnssiAdDerElement {
    <#
    .SYNOPSIS
    Splits a range of DER-encoded bytes into its consecutive elements.

    .DESCRIPTION
    Reads the tag, the length and the position of the content of each element found between
    Offset and End (by default, the end of the data). Pass an element's ContentOffset and End to
    read the children of a SEQUENCE. Only single-byte tags and definite lengths of up to four
    bytes are read, which covers certificates and keys. Throws when an element runs past the end
    of the range or uses a length form it does not read.

    .PARAMETER Byte
    The DER-encoded data.

    .PARAMETER Offset
    The position of the first element. 0 by default.

    .PARAMETER End
    The position just after the last element. The length of the data by default.

    .EXAMPLE
    Get-MtAnssiAdDerElement -Byte $certificate

    Returns the outer SEQUENCE of a certificate, with Tag 0x30.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Byte,

        [int] $Offset = 0,

        [int] $End = -1
    )

    if ($End -lt 0) { $End = $Byte.Length }
    $position = $Offset
    while ($position -lt $End) {
        $tag = [int]$Byte[$position]
        $length = [int]$Byte[$position + 1]
        $content = $position + 2
        if ($length -ge 0x80) {
            $size = $length - 0x80
            if ($size -notin 1..4) { throw "The DER length at offset $position cannot be read." }
            $length = 0
            for ($index = 0; $index -lt $size; $index++) {
                $length = $length * 256 + $Byte[$content + $index]
            }
            $content += $size
        }
        if ($content + $length -gt $End) { throw "The DER data is truncated at offset $position." }
        [PSCustomObject]@{
            Tag           = $tag
            ContentOffset = $content
            Length        = $length
            End           = $content + $length
        }
        $position = $content + $length
    }
}
