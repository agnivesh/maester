function Test-MtAnssiAdKrbtgtPasswordAge {
    <#
    .SYNOPSIS
    ANSSI-AD-045: The krbtgt account password should be changed at least once a year.

    .DESCRIPTION
    Fails when the password of the krbtgt account of the domain was last set more than a year ago,
    or never. The account is identified by its relative identifier 502.

    The test is skipped when no account with relative identifier 502 is in the collected data,
    because the age of the password is then unknown.

    Corresponds to the ANSSI Active Directory checkpoint vuln_krbtgt.

    .EXAMPLE
    Test-MtAnssiAdKrbtgtPasswordAge

    Returns $true when the krbtgt password changed within the last year, $false when it did not,
    and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdKrbtgtPasswordAge
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-045',
        Title = 'The krbtgt account password should be changed at least once a year',
        Product = 'ad',
        Feature = 'account-security',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1558.001',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdKrbtgtPasswordAge'

    $now = (Get-Date).ToUniversalTime()
    $oldestAcceptable = $now.AddYears(-1)

    $adState = Get-MtADDomainState -Categories @('Users')

    $krbtgtAccounts = @($adState.Users |
            Where-Object { ([string]$_.Sid.Value) -match '-502$' })
    Write-Verbose "Accounts with relative identifier 502: $($krbtgtAccounts.Count)"

    if ($krbtgtAccounts.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The krbtgt account (relative identifier 502) was not found in the collected data.')
        return $null
    }

    $staleAccounts = @($krbtgtAccounts | Where-Object {
            $null -eq $_.PasswordLastSet -or $_.PasswordLastSet -lt $oldestAcceptable
        })

    if ($staleAccounts.Count -eq 0) {
        $changed = Format-MtAnssiAdDate $krbtgtAccounts[0].PasswordLastSet
        Add-MtTestResultDetail -Result "The krbtgt password was last changed on $changed."
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $staleAccounts -Column ([ordered]@{
            'Account'           = { $_.SamAccountName }
            'Password last set' = { Format-MtAnssiAdDate $_.PasswordLastSet }
            'Age in days'       = {
                if ($null -eq $_.PasswordLastSet) {
                    'n/a'
                } else {
                    [int]($now - $_.PasswordLastSet).TotalDays
                }
            }
        })

    $result = "The krbtgt account password has not been changed for more than a year. An " +
        "attacker holding a copy of the account database can forge tickets (golden tickets) " +
        "for as long as the password stays the same.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
