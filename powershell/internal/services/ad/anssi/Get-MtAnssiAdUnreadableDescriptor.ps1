function Get-MtAnssiAdUnreadableDescriptor {
    <#
    .SYNOPSIS
    Lists the accounts whose security descriptor cannot be read.

    .DESCRIPTION
    Reads the nTSecurityDescriptor attribute (owner, group and DACL) of each account with one
    base-scope LDAP search over a single connection. An account is returned when the search gives
    back no descriptor, which is what Active Directory does when the reading account is not
    allowed to see it. Throws when a search fails, so that a failed read is never reported as an
    unreadable descriptor or as a readable one.

    .PARAMETER Account
    The accounts to check, each with a DistinguishedName, for example the Account list of
    Get-MtAnssiAdPrivilegedAccount.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdUnreadableDescriptor -Account $privileged.Account `
        -ProtocolEvidence $adState.ProtocolEvidence

    Returns the accounts whose security descriptor could not be read.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Account,

        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $flags = [System.DirectoryServices.SecurityMasks]::Owner -bor
    [System.DirectoryServices.SecurityMasks]::Group -bor
    [System.DirectoryServices.SecurityMasks]::Dacl
    $unreadable = [System.Collections.Generic.List[object]]::new()
    $connection = $null
    try {
        $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
        foreach ($item in $Account) {
            $entry = Invoke-MtLdapSearch -Connection $connection `
                -SearchBase $item.DistinguishedName -Scope Base `
                -Attributes @('nTSecurityDescriptor') -PageSize 0 `
                -SecurityDescriptorFlags $flags | Select-Object -First 1
            if ($null -eq $entry.nTSecurityDescriptor) {
                $unreadable.Add($item)
            }
        }
    } finally {
        if ($null -ne $connection) {
            $connection.Dispose()
        }
    }

    Write-Verbose "Security descriptors not readable: $($unreadable.Count) of $(@($Account).Count)"
    return $unreadable.ToArray()
}
