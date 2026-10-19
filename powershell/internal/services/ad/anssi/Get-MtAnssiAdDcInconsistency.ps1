function Get-MtAnssiAdDcInconsistency {
    <#
    .SYNOPSIS
    Finds the inconsistent attributes of domain controller computer accounts.

    .DESCRIPTION
    A writable domain controller computer account must have the SERVER_TRUST_ACCOUNT and
    TRUSTED_FOR_DELEGATION flags in userAccountControl and a domain controller entry (a server
    object with an NTDS Settings child of class nTDSDSA) that points to it.

    A read-only domain controller computer account must have the PARTIAL_SECRETS_ACCOUNT,
    TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION and WORKSTATION_TRUST_ACCOUNT flags. It must not have a
    writable entry. Its own server object and NTDS Settings object of class nTDSDSARO are not in
    the collected data and are not verified.

    .PARAMETER Controller
    The domain controllers, as returned by Get-MtAnssiAdDomainController.

    .EXAMPLE
    Get-MtAnssiAdDcInconsistency -Controller $controllers

    Returns one object with Name, Type and Problem for each inconsistency found.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Controller
    )

    # The leading commas keep each flag an array instead of letting the outer array flatten it.
    $requiredFlags = @{
        Writable = @(
            , @('SERVER_TRUST_ACCOUNT', 0x2000)
            , @('TRUSTED_FOR_DELEGATION', 0x80000)
        )
        ReadOnly = @(
            , @('PARTIAL_SECRETS_ACCOUNT', 0x04000000)
            , @('TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION', 0x01000000)
            , @('WORKSTATION_TRUST_ACCOUNT', 0x1000)
        )
    }
    $entryProblem = @{
        'Writable:False' = 'No domain controller entry (server object with an NTDS Settings ' +
        'object of class nTDSDSA) points to the computer account.'
        'ReadOnly:True'  = 'A writable domain controller entry (NTDS Settings object of class ' +
        'nTDSDSA) points to this read-only domain controller.'
    }

    $problems = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Controller) {
        $name = $item.Computer.Name
        $flags = [int]$item.Computer.UserAccountControl

        foreach ($required in $requiredFlags[$item.Type]) {
            if (($flags -band $required[1]) -ne $required[1]) {
                $problems.Add([PSCustomObject]@{
                        Name    = $name
                        Type    = $item.Type
                        Problem = "The userAccountControl attribute lacks the $($required[0]) flag."
                    })
            }
        }

        $key = '{0}:{1}' -f $item.Type, ($null -ne $item.DomainController)
        if ($entryProblem.ContainsKey($key)) {
            $problems.Add([PSCustomObject]@{
                    Name    = $name
                    Type    = $item.Type
                    Problem = $entryProblem[$key]
                })
        }
    }

    return $problems.ToArray()
}
