function Get-MtLdapSecurityDescriptorAllowSid {
    <#
    .SYNOPSIS
    Returns the SIDs of the allow entries of a binary security descriptor.

    .DESCRIPTION
    Walks the discretionary access control list (DACL) of a self-relative security descriptor,
    as stored in Active Directory, and returns the SID of every access-allowed entry
    (ACCESS_ALLOWED_ACE and ACCESS_ALLOWED_OBJECT_ACE), in order. Deny and other entries are
    skipped. A descriptor without a DACL, or without allow entries, gives nothing.

    The entries are read by Get-MtLdapSecurityDescriptorAce, byte by byte, so this works on every
    platform, unlike the .NET access control classes, which are not supported outside Windows.
    Throws when the descriptor is malformed.

    .PARAMETER Descriptor
    The bytes of the security descriptor.

    .EXAMPLE
    Get-MtLdapSecurityDescriptorAllowSid -Descriptor $bytes

    Returns the SIDs that the descriptor allows.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Descriptor
    )

    foreach ($ace in @(Get-MtLdapSecurityDescriptorAce -Descriptor $Descriptor)) {
        if ($ace.Type -eq 'Allow') {
            $ace.Sid
        }
    }
}
