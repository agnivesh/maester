function Select-MtAnssiAdCountedPrivilegedAccount {
    <#
    .SYNOPSIS
    Keeps the privileged accounts that count towards the number of privileged group members.

    .DESCRIPTION
    Keeps the accounts that are members of a protected group, directly, through nesting or
    through their primary group, and leaves out, as ANSSI does, the built-in Administrator
    account (RID 500) and the domain controller accounts. Accounts that are privileged only as
    protected accounts (krbtgt) are left out too, since they are not group members.

    .PARAMETER Account
    The Account list of Get-MtAnssiAdPrivilegedAccount.

    .PARAMETER DomainController
    The domain controllers, as returned by Get-MtAnssiAdDomainController.

    .PARAMETER DomainSid
    The SID of the collected domain.

    .EXAMPLE
    Select-MtAnssiAdCountedPrivilegedAccount -Account $privileged.Account `
        -DomainController $controllers -DomainSid $domainSid

    Returns the accounts to count.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Account,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $DomainController,

        [Parameter(Mandatory)]
        [string] $DomainSid
    )

    $controllerDn = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($controller in $DomainController) {
        $null = $controllerDn.Add([string]$controller.Computer.DistinguishedName)
    }
    $administratorSid = "$DomainSid-500"

    foreach ($item in $Account) {
        $isMember = @($item.Link -ne 'ProtectedAccount').Count -gt 0
        $isExcluded = $controllerDn.Contains($item.DistinguishedName) -or
            [string]$item.Item.Sid.Value -eq $administratorSid
        if ($isMember -and -not $isExcluded) {
            $item
        }
    }
}
