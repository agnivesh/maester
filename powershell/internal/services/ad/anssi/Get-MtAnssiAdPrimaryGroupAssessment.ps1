function Get-MtAnssiAdPrimaryGroupAssessment {
    <#
    .SYNOPSIS
    Compares the primary group of user and computer accounts with the default of their type.

    .DESCRIPTION
    Returns one object for each account that has a primary group ID, with the default values for
    its type and whether the account deviates from them. Accounts without a primary group ID in
    the collected data are not returned: nothing can be said about them.

    Defaults: user accounts 513 (Domain Users) or 514 (Domain Guests), computer accounts 515
    (Domain Computers), writable domain controllers 516 (Domain Controllers), read-only domain
    controllers 521 (Read-only Domain Controllers). A computer is a read-only domain controller
    when its userAccountControl has PARTIAL_SECRETS_ACCOUNT (0x04000000), and a writable one when
    it has SERVER_TRUST_ACCOUNT (0x2000).

    .PARAMETER User
    The user accounts, as collected for the Users category.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .EXAMPLE
    Get-MtAnssiAdPrimaryGroupAssessment -User $users -Computer $computers | Where-Object IsDeviation

    Returns the accounts whose primary group is not the default of their type.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object[]] $User,

        [AllowNull()]
        [object[]] $Computer
    )

    $partialSecrets = 0x04000000
    $serverTrust = 0x2000
    $assessed = [System.Collections.Generic.List[object]]::new()

    $accounts = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $User) {
        $accounts.Add(@{ Item = $item; Type = 'User'; Expected = @(513, 514) })
    }
    foreach ($item in $Computer) {
        $type = 'Computer'
        $expected = @(515)
        if (($item.UserAccountControl -band $partialSecrets) -ne 0) {
            $type = 'ReadOnlyDomainController'
            $expected = @(521)
        } elseif (($item.UserAccountControl -band $serverTrust) -ne 0) {
            $type = 'DomainController'
            $expected = @(516)
        }
        $accounts.Add(@{ Item = $item; Type = $type; Expected = $expected })
    }

    foreach ($account in $accounts) {
        $groupId = 0
        if (-not [int]::TryParse([string]$account.Item.PrimaryGroupId, [ref]$groupId)) {
            continue
        }

        $assessed.Add([PSCustomObject]@{
                DistinguishedName = $account.Item.DistinguishedName
                Name              = $account.Item.Name
                Type              = $account.Type
                Enabled           = $account.Item.Enabled
                PrimaryGroupId    = $groupId
                Expected          = ($account.Expected -join ' or ')
                IsDeviation       = $account.Expected -notcontains $groupId
            })
    }

    return $assessed.ToArray()
}
