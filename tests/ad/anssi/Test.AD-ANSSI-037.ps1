function Test-MtAnssiAdAccountDormant {
    <#
    .SYNOPSIS
    ANSSI-AD-037: No more than 25% of enabled accounts should be dormant.

    .DESCRIPTION
    Counts the dormant enabled user and computer accounts and fails when they are more than 25%
    of the enabled accounts.

    An account is dormant when both of the following apply:
    - Its password was last set more than three years ago, or never.
    - It has not authenticated for more than a year, or it was created more than a year ago and
      never authenticated.

    Corresponds to the ANSSI Active Directory checkpoint vuln_user_accounts_dormant.

    .EXAMPLE
    Test-MtAnssiAdAccountDormant

    Returns $true when at most 25% of the enabled accounts are dormant, $false when more are, and
    $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdAccountDormant
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-037',
        Title = 'No more than 25% of enabled accounts should be dormant',
        Product = 'ad',
        Feature = 'users',
        Area = 'identity-lifecycle',
        ResourceType = 'User',
        Severity = 'Low',
        UserImpact = 'Low',
        ImplementationCost = 'High',
        Mitre = 'T1078',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdAccountDormant'

    $maxPercentage = 25
    $now = (Get-Date).ToUniversalTime()
    $cutoffs = @{ PasswordCutoff = $now.AddYears(-3); ActivityCutoff = $now.AddYears(-1) }

    $adState = Get-MtADDomainState -Categories @('Users', 'Computers')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Users', 'Computers'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $users = Get-MtAnssiAdDormantAccount -Account $adState.Users -Type User @cutoffs
    $computers = Get-MtAnssiAdDormantAccount -Account $adState.Computers -Type Computer @cutoffs
    $enabledCount = $users.EnabledCount + $computers.EnabledCount
    $dormantAccounts = @($users.Dormant) + @($computers.Dormant)
    Write-Verbose "Enabled: $enabledCount, dormant: $($dormantAccounts.Count)"

    if ($enabledCount -eq 0) {
        Add-MtTestResultDetail -Result 'No enabled account was found in the domain.'
        return $true
    }

    $percentage = [Math]::Round(100 * $dormantAccounts.Count / $enabledCount, 1)
    $summary = "$($dormantAccounts.Count) of $enabledCount enabled accounts ($percentage%) " +
        'are dormant.'

    if ($dormantAccounts.Count * 100 -le $enabledCount * $maxPercentage) {
        Add-MtTestResultDetail -Result "$summary The limit is $maxPercentage%."
        return $true
    }

    $oldestFirst = @($dormantAccounts | Sort-Object -Property PasswordLastSet)
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $oldestFirst -Column ([ordered]@{
            'Type'              = { $_.Type }
            'Account'           = { $_.SamAccountName }
            'Password last set' = { Format-MtAnssiAdDate $_.PasswordLastSet }
            'Last logon'        = { Format-MtAnssiAdDate $_.LastLogonDate }
            'Created'           = { Format-MtAnssiAdDate $_.Created }
        })

    $result = "$summary This is more than the $maxPercentage% limit. Obsolete accounts grant " +
        "illegitimate access and can be used stealthily by an attacker.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
