function Get-MtAnssiAdSiloAssignment {
    <#
    .SYNOPSIS
    Finds how each account stands with its authentication policy silo.

    .DESCRIPTION
    Reads msDS-AssignedAuthNPolicySilo of each account with a base-scope LDAP search, reads each
    assigned silo once (Read-MtAnssiAdAuthenticationSilo), and returns one object per account
    with Account, Silo (the silo name, or empty) and Problem: 'not assigned to a silo', 'silo not
    enforced', 'not granted access to the silo', or $null when the account is properly in an
    enforced silo. Throws when a read fails.

    .PARAMETER Account
    The accounts to check, each with a DistinguishedName.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdSiloAssignment -Account $accounts -ProtocolEvidence $adState.ProtocolEvidence

    Returns the silo status of each account.
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

    $silos = @{}
    $result = [System.Collections.Generic.List[object]]::new()
    $connection = $null
    try {
        $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
        foreach ($item in $Account) {
            $entry = Invoke-MtLdapSearch -Connection $connection `
                -SearchBase $item.DistinguishedName -Scope Base -PageSize 0 `
                -Attributes @('msDS-AssignedAuthNPolicySilo') | Select-Object -First 1
            $siloDn = [string]$entry.'msDS-AssignedAuthNPolicySilo'
            $siloName = ''
            $problem = 'not assigned to a silo'
            if ($siloDn) {
                if (-not $silos.ContainsKey($siloDn)) {
                    $silos[$siloDn] = Read-MtAnssiAdAuthenticationSilo -Connection $connection `
                        -DistinguishedName $siloDn
                }
                $silo = $silos[$siloDn]
                $siloName = $silo.Name
                $problem = $null
                if (-not $silo.Enforced) {
                    $problem = 'silo not enforced'
                } elseif (-not $silo.Member.Contains($item.DistinguishedName)) {
                    $problem = 'not granted access to the silo'
                }
            }
            $result.Add([PSCustomObject]@{ Account = $item; Silo = $siloName; Problem = $problem })
        }
    } finally {
        if ($null -ne $connection) {
            $connection.Dispose()
        }
    }

    return $result.ToArray()
}
