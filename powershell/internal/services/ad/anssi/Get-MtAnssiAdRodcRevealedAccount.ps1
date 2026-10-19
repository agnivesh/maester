function Get-MtAnssiAdRodcRevealedAccount {
    <#
    .SYNOPSIS
    Lists the accounts whose secrets have been revealed to (cached on) read-only domain controllers.

    .DESCRIPTION
    Reads the msDS-RevealedUsers attribute of each read-only domain controller (RODC) with ranged
    LDAP reads over one connection, so that an RODC that cached very many secrets is read in
    full. Each value is a DN-with-binary string (B:<length>:<hex>:<distinguished name>), one per
    cached secret attribute. Returns one object per account of the given list that is revealed
    to an RODC, with the Account and the Controller. Throws when a read fails.

    .PARAMETER Controller
    The read-only domain controllers, as returned by Get-MtAnssiAdDomainController.

    .PARAMETER Account
    The accounts to look for, each with a DistinguishedName, for example the Account list of
    Get-MtAnssiAdPrivilegedAccount.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdRodcRevealedAccount -Controller $rodcs -Account $privileged.Account `
        -ProtocolEvidence $adState.ProtocolEvidence

    Returns one Account and Controller pair per privileged account cached on an RODC.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Controller,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Account,

        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $revealed = [System.Collections.Generic.List[object]]::new()
    $connection = $null
    try {
        $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
        foreach ($rodc in $Controller) {
            $cachedDn = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase)
            foreach ($value in @(Get-MtLdapRangedValue -Connection $connection `
                        -DistinguishedName $rodc.Computer.DistinguishedName `
                        -AttributeName 'msDS-RevealedUsers')) {
                $null = $cachedDn.Add(([string]$value -replace '^B:\d+:[0-9A-Fa-f]*:', ''))
            }
            foreach ($item in $Account) {
                if ($cachedDn.Contains($item.DistinguishedName)) {
                    $revealed.Add([PSCustomObject]@{ Account = $item; Controller = $rodc })
                }
            }
        }
    } finally {
        if ($null -ne $connection) {
            $connection.Dispose()
        }
    }

    return $revealed.ToArray()
}
