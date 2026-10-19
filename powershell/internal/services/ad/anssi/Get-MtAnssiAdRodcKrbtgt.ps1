function Get-MtAnssiAdRodcKrbtgt {
    <#
    .SYNOPSIS
    Finds the krbtgt accounts of read-only domain controllers and whether a computer uses them.

    .DESCRIPTION
    Every read-only domain controller (RODC) has its own krbtgt account, named krbtgt_ followed by
    a number, and its computer account points to it through msDS-KrbTgtLink. Returns one object
    for each user account whose name starts with krbtgt_, with the name of the computer that
    points to it, or no computer when the account is an orphan. The built-in krbtgt account,
    which has no suffix, is not returned.

    Names and distinguished names are compared without regard to case (hashtable keys and the
    -like operator ignore it).

    .PARAMETER User
    The user accounts, as collected for the Users category.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category, with KrbTgtLink.

    .EXAMPLE
    Get-MtAnssiAdRodcKrbtgt -User $users -Computer $computers | Where-Object IsOrphan

    Returns the RODC krbtgt accounts that no computer account points to.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object[]] $User,

        [AllowNull()]
        [object[]] $Computer
    )

    $owners = @{}
    foreach ($item in $Computer) {
        if ($item.KrbTgtLink) {
            $owners[[string]$item.KrbTgtLink] = $item.Name
        }
    }

    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $User) {
        if (([string]$item.SamAccountName) -notlike 'krbtgt_*') {
            continue
        }

        $owner = $owners[[string]$item.DistinguishedName]
        $found.Add([PSCustomObject]@{
                DistinguishedName = $item.DistinguishedName
                Name              = $item.Name
                SamAccountName    = $item.SamAccountName
                Enabled           = $item.Enabled
                Created           = $item.Created
                PasswordLastSet   = $item.PasswordLastSet
                Computer          = $owner
                IsOrphan          = $null -eq $owner
            })
    }

    return $found.ToArray()
}
