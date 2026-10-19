function Get-MtAnssiAdServiceAccount {
    <#
    .SYNOPSIS
    Finds the enabled user accounts that have a service principal name.

    .DESCRIPTION
    Returns one object for each enabled user account with at least one service principal name,
    with its first name, its msDS-SupportedEncryptionTypes value and whether that value declares
    AES128 (0x8) or AES256 (0x10). An account without a value, or with 0, does not declare AES.

    Computer accounts are not in the users, and disabled accounts are skipped.

    .PARAMETER User
    The user accounts, as collected for the Users category.

    .EXAMPLE
    Get-MtAnssiAdServiceAccount -User $users | Where-Object { -not $_.SupportsAes }

    Returns the service accounts that do not declare support for Kerberos AES encryption.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object[]] $User
    )

    $aesBits = 0x18
    $accounts = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $User) {
        $names = @($item.ServicePrincipalName | Where-Object { $_ })
        if ($item.Enabled -ne $true -or $names.Count -eq 0) {
            continue
        }

        $accounts.Add([PSCustomObject]@{
                DistinguishedName        = $item.DistinguishedName
                Name                     = $item.Name
                ServicePrincipalName     = $names[0]
                SupportedEncryptionTypes = $item.SupportedEncryptionTypes
                LastLogonDate            = $item.LastLogonDate
                SupportsAes              = ($item.SupportedEncryptionTypes -band $aesBits) -ne 0
            })
    }

    return $accounts.ToArray()
}
