function Get-MtAnssiAdKeyAdminsAceIsBroad {
    <#
    .SYNOPSIS
    Returns whether an access control entry gives more than the narrow Key Admins grant.

    .DESCRIPTION
    The narrow grant is reading and writing the msDS-KeyCredentialLink attribute. An entry is broad
    when its mask holds any of: create or delete child objects, delete, delete tree, write
    permissions, write owner, extended rights, GenericWrite or GenericAll, or the right to write a
    property other than msDS-KeyCredentialLink (an entry without an object type writes them all).
    Reading properties, listing and reading permissions are not broad.

    .PARAMETER Ace
    One DACL entry, with Mask and ObjectType.

    .EXAMPLE
    Get-MtAnssiAdKeyAdminsAceIsBroad -Ace $entry

    Returns $true for GenericAll, $false for read and write on msDS-KeyCredentialLink.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [object] $Ace
    )

    $keyCredentialLink = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
    $broadBits = [int64](0x10000000 + 0x40000000 + 0x80000 + 0x40000 + 0x10000 +
        0x100 + 0x40 + 0x2 + 0x1)
    $mask = [int64][uint32]$Ace.Mask

    $writesOtherProperty = ($mask -band 0x20) -ne 0 -and
        [string]$Ace.ObjectType -ne $keyCredentialLink
    return (($mask -band $broadBits) -ne 0) -or $writesOtherProperty
}
