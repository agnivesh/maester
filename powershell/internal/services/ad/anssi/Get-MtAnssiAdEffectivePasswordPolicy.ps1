function Get-MtAnssiAdEffectivePasswordPolicy {
    <#
    .SYNOPSIS
    Finds the password policy that applies to each account and what makes it weak.

    .DESCRIPTION
    Reads msDS-ResultantPSO of each account with a base-scope LDAP search, which gives the
    fine-grained password policy (PSO) the domain controller applies to it, precedence already
    resolved. Reads each such PSO once. An account without a resultant PSO gets the domain
    password policy. Returns one object per account with Account, Source (the policy), MinLength,
    MaxAge and Weakness (from Get-MtAnssiAdPasswordPolicyWeakness). Throws when a read fails or a
    PSO cannot be read.

    .PARAMETER Account
    The accounts to check, each with a DistinguishedName.

    .PARAMETER Domain
    The collected domain, whose MinPwdLength and MaxPwdAge are the domain password policy.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdEffectivePasswordPolicy -Account $users -Domain $adState.Domain `
        -ProtocolEvidence $adState.ProtocolEvidence

    Returns the effective policy of each account.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Account,

        [Parameter(Mandatory)]
        [object] $Domain,

        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $domainPolicy = [PSCustomObject]@{
        Source    = 'Domain password policy'
        MinLength = $Domain.MinPwdLength
        MaxAge    = $Domain.MaxPwdAge
    }
    $settings = @{}
    $result = [System.Collections.Generic.List[object]]::new()
    $connection = $null
    try {
        $connection = New-MtAdProtocolConnection -ProtocolEvidence $ProtocolEvidence
        foreach ($item in $Account) {
            $entry = Invoke-MtLdapSearch -Connection $connection `
                -SearchBase $item.DistinguishedName -Scope Base -PageSize 0 `
                -Attributes @('msDS-ResultantPSO') | Select-Object -First 1
            $psoDn = [string]$entry.'msDS-ResultantPSO'
            $policy = $domainPolicy
            if ($psoDn) {
                if (-not $settings.ContainsKey($psoDn)) {
                    $settings[$psoDn] = Read-MtAnssiAdPasswordSetting -Connection $connection `
                        -DistinguishedName $psoDn
                }
                $policy = $settings[$psoDn]
            }
            $result.Add([PSCustomObject]@{
                    Account   = $item
                    Source    = $policy.Source
                    MinLength = $policy.MinLength
                    MaxAge    = $policy.MaxAge
                    Weakness  = @(Get-MtAnssiAdPasswordPolicyWeakness -MinLength $policy.MinLength `
                            -MaxAge $policy.MaxAge)
                })
        }
    } finally {
        if ($null -ne $connection) {
            $connection.Dispose()
        }
    }

    return $result.ToArray()
}
