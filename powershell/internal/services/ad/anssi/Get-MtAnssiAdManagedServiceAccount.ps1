function Get-MtAnssiAdManagedServiceAccount {
    <#
    .SYNOPSIS
    Finds the group managed and standalone managed service accounts among the computers.

    .DESCRIPTION
    Managed service accounts are objects of the computer class. Returns one object for each
    computer whose object classes include msDS-GroupManagedServiceAccount (Type gMSA) or
    msDS-ManagedServiceAccount (Type MSA), with the properties the date checks need. Delegated
    managed service accounts and ordinary computers are not returned.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category, with ObjectClass.

    .EXAMPLE
    Get-MtAnssiAdManagedServiceAccount -Computer $computers

    Returns the gMSAs and MSAs with Name, Type, Enabled, PasswordLastSet and LastLogonDate.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object[]] $Computer
    )

    $accounts = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Computer) {
        $type = $null
        if ($item.ObjectClass -contains 'msDS-GroupManagedServiceAccount') {
            $type = 'gMSA'
        } elseif ($item.ObjectClass -contains 'msDS-ManagedServiceAccount') {
            $type = 'MSA'
        } else {
            continue
        }

        $accounts.Add([PSCustomObject]@{
                DistinguishedName = $item.DistinguishedName
                Name              = $item.Name
                Type              = $type
                Enabled           = $item.Enabled
                PasswordLastSet   = $item.PasswordLastSet
                LastLogonDate     = $item.LastLogonDate
            })
    }

    return $accounts.ToArray()
}
