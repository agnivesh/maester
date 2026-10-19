function Test-MtAnssiAdTrustAccountPasswordAge {
    <#
    .SYNOPSIS
    ANSSI-AD-055: Trust account passwords should be changed at least once a year.

    .DESCRIPTION
    Reports trust accounts whose password has not been changed for more than a year, or never.

    A trust account is a user account with INTERDOMAIN_TRUST_ACCOUNT (0x800) set in its
    userAccountControl. A stale password can mean the trust relationship was deleted while its
    account remained, or that the automatic password change of an active trust does not work.

    Corresponds to the ANSSI Active Directory checkpoint vuln_trusts_accounts.

    .EXAMPLE
    Test-MtAnssiAdTrustAccountPasswordAge

    Returns $true when every trust account password changed within the last year, $false when at
    least one did not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdTrustAccountPasswordAge
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-055',
        Title = 'Trust account passwords should be changed at least once a year',
        Product = 'ad',
        Feature = 'trusts',
        Area = 'access-control',
        ResourceType = 'Trust',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1558',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdTrustAccountPasswordAge'

    $interdomainTrustAccount = 0x800
    $oldestAcceptable = (Get-Date).ToUniversalTime().AddYears(-1)

    $adState = Get-MtADDomainState -Categories @('Users')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Users'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $trustAccounts = @($adState.Users | Where-Object {
            ($_.UserAccountControl -band $interdomainTrustAccount) -ne 0
        })
    $staleAccounts = @($trustAccounts | Where-Object {
            $null -eq $_.PasswordLastSet -or $_.PasswordLastSet -lt $oldestAcceptable
        })
    Write-Verbose "Trust accounts: $($trustAccounts.Count), stale: $($staleAccounts.Count)"

    if ($staleAccounts.Count -eq 0) {
        $summary = 'The password of every trust account was changed within the last year.'
        if ($trustAccounts.Count -eq 0) {
            $summary = 'No trust account was found in the domain.'
        }
        Add-MtTestResultDetail -Result $summary
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $staleAccounts -Column ([ordered]@{
            'Trust account'      = { $_.SamAccountName }
            'Password last set'  = { Format-MtAnssiAdDate $_.PasswordLastSet }
            'Distinguished name' = { $_.DistinguishedName }
        })

    $result = "Found $($staleAccounts.Count) trust account(s) whose password has not changed " +
        "for more than a year. The trust relationship may have been deleted while its account " +
        "remains, or its automatic password change may not work.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
