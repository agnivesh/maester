function Get-MtAnssiAdDormantAccount {
    <#
    .SYNOPSIS
    Finds the dormant accounts among user or computer accounts.

    .DESCRIPTION
    Goes through the accounts once and skips the disabled ones. An enabled account is dormant when
    its password was last set before PasswordCutoff, or never, and its last activity is before
    ActivityCutoff. The last activity is the last logon, or the creation date for an account that
    never logged on.

    A plain loop is used on purpose: directories can hold hundreds of thousands of accounts and
    a script block per account is several times slower.

    .PARAMETER Account
    The accounts, as collected for the Users or Computers category.

    .PARAMETER Type
    The text stored in the Type of each dormant account, for example User or Computer.

    .PARAMETER PasswordCutoff
    Accounts whose password was set after this date are not dormant.

    .PARAMETER ActivityCutoff
    Accounts that were active after this date are not dormant.

    .EXAMPLE
    Get-MtAnssiAdDormantAccount -Account $users -Type User -PasswordCutoff $a -ActivityCutoff $b

    Returns the number of enabled accounts and the dormant ones.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Account,

        [Parameter(Mandatory)]
        [string] $Type,

        [Parameter(Mandatory)]
        [datetime] $PasswordCutoff,

        [Parameter(Mandatory)]
        [datetime] $ActivityCutoff
    )

    Write-Verbose "Looking for dormant $Type accounts."

    $enabledCount = 0
    $dormant = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $Account) {
        if ($item.Enabled -ne $true) { continue }
        $enabledCount++

        $lastActivity = $item.LastLogonDate
        if ($null -eq $lastActivity) { $lastActivity = $item.Created }
        $passwordOld = $null -eq $item.PasswordLastSet -or $item.PasswordLastSet -lt $PasswordCutoff
        $inactive = $null -eq $lastActivity -or $lastActivity -lt $ActivityCutoff

        if ($passwordOld -and $inactive) {
            $dormant.Add([PSCustomObject]@{
                    Type            = $Type
                    SamAccountName  = $item.SamAccountName
                    PasswordLastSet = $item.PasswordLastSet
                    LastLogonDate   = $item.LastLogonDate
                    Created         = $item.Created
                })
        }
    }

    return [PSCustomObject]@{
        EnabledCount = $enabledCount
        Dormant      = $dormant.ToArray()
    }
}
