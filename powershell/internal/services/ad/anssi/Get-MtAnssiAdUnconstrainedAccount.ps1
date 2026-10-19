function Get-MtAnssiAdUnconstrainedAccount {
    <#
    .SYNOPSIS
    Finds the enabled accounts trusted for unconstrained delegation, except domain controllers.

    .DESCRIPTION
    An enabled user or computer account is returned when it has the TRUSTED_FOR_DELEGATION flag.
    Domain controllers, writable or read-only, are left out: unconstrained delegation is their
    default. Disabled accounts are left out because they cannot authenticate.

    The accounts are read in plain loops: directories can hold hundreds of thousands of accounts
    and a script block per account is several times slower.

    .PARAMETER User
    The user accounts, as collected for the Users category.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .PARAMETER DomainController
    The domain controller entries, as collected for the DomainControllers category.

    .EXAMPLE
    Get-MtAnssiAdUnconstrainedAccount -User $users -Computer $computers -DomainController $entries

    Returns one object with Type, Name, OperatingSystem and LastLogonDate for each account.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $User,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Computer,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $DomainController
    )

    $controllers = @(Get-MtAnssiAdDomainController -Computer $Computer `
            -DomainController $DomainController)
    $controllerNames = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($controllers.Computer.DistinguishedName))

    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $User) {
        if ($item.Enabled -eq $true -and $item.TrustedForDelegation -eq $true) {
            $found.Add([PSCustomObject]@{
                    Type            = 'User'
                    Name            = $item.SamAccountName
                    OperatingSystem = $null
                    LastLogonDate   = $item.LastLogonDate
                })
        }
    }
    foreach ($item in $Computer) {
        if ($item.Enabled -eq $true -and $item.TrustedForDelegation -eq $true -and
            -not $controllerNames.Contains([string]$item.DistinguishedName)) {
            $found.Add([PSCustomObject]@{
                    Type            = 'Computer'
                    Name            = $item.SamAccountName
                    OperatingSystem = $item.OperatingSystem
                    LastLogonDate   = $item.LastLogonDate
                })
        }
    }

    Write-Verbose "Accounts trusted for unconstrained delegation: $($found.Count)"
    return $found.ToArray()
}
