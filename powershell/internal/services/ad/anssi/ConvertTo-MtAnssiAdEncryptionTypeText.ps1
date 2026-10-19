function ConvertTo-MtAnssiAdEncryptionTypeText {
    <#
    .SYNOPSIS
    Describes the value of msDS-SupportedEncryptionTypes in words.

    .DESCRIPTION
    The attribute is a bit mask: 0x1 DES-CBC-CRC, 0x2 DES-CBC-MD5, 0x4 RC4-HMAC, 0x8 AES128-SHA1,
    0x10 AES256-SHA1, 0x20 AES session keys. A missing value or 0 means the attribute is not set:
    the domain controllers then assume the default of the domain. Bits that are not listed are
    shown as a number.

    .PARAMETER Value
    The attribute value, or $null when it is not set.

    .EXAMPLE
    ConvertTo-MtAnssiAdEncryptionTypeText -Value 28

    Returns RC4, AES128, AES256 (0x1C).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object] $Value
    )

    $number = 0
    if (-not [int]::TryParse([string]$Value, [ref]$number) -or $number -eq 0) {
        return 'Not set'
    }

    $types = @(
        @{ Bit = 1; Name = 'DES-CBC-CRC' }
        @{ Bit = 2; Name = 'DES-CBC-MD5' }
        @{ Bit = 4; Name = 'RC4' }
        @{ Bit = 8; Name = 'AES128' }
        @{ Bit = 16; Name = 'AES256' }
        @{ Bit = 32; Name = 'AES session keys' }
    )
    $parts = [System.Collections.Generic.List[string]]::new()
    $known = 0
    foreach ($type in $types) {
        if (($number -band $type.Bit) -ne 0) {
            $parts.Add($type.Name)
            $known = $known -bor $type.Bit
        }
    }
    if (($number -band (-bnot $known)) -ne 0) {
        $parts.Add('other bits')
    }

    return '{0} (0x{1:X})' -f ($parts -join ', '), $number
}
