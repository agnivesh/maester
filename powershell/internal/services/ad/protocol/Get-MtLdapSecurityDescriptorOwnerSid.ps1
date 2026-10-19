function Get-MtLdapSecurityDescriptorOwnerSid {
    <#
    .SYNOPSIS
    Returns the owner SID of a security descriptor read over LDAP.

    .DESCRIPTION
    Accepts the nTSecurityDescriptor value as Invoke-MtLdapSearch returns it: the raw
    self-relative bytes (on platforms where Windows security classes are not available) or the
    parsed descriptor of ConvertFrom-MtLdapSecurityDescriptor (on Windows). Reads the owner
    offset from the descriptor header and the SID at that offset byte by byte. Returns $null when
    there is no descriptor or no owner.

    .PARAMETER Descriptor
    The nTSecurityDescriptor value.

    .EXAMPLE
    Get-MtLdapSecurityDescriptorOwnerSid -Descriptor $entry.nTSecurityDescriptor

    Returns the owner SID as text, for example S-1-5-21-1-2-3-512.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object] $Descriptor
    )

    if ($Descriptor -is [byte[]]) {
        if ($Descriptor.Length -lt 20) {
            return $null
        }
        $offset = [BitConverter]::ToInt32($Descriptor, 4)
        if ($offset -eq 0) {
            return $null
        }
        return ConvertFrom-MtLdapBinarySid -Bytes $Descriptor -Offset $offset
    }

    return $Descriptor.Owner.Sid
}
