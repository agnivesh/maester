function Test-MtAnssiAdUserNeverExpiringPassword {
    <#
    .SYNOPSIS
    ANSSI-AD-041: No more than 10% of accounts should have a never-expiring password.

    .DESCRIPTION
    Counts the enabled user accounts whose password never expires (DONT_EXPIRE_PASSWORD, 0x10000)
    and fails when they are more than 10% of the enabled user accounts. Disabled accounts are
    ignored, in the count and in the total.

    Corresponds to the ANSSI Active Directory checkpoint vuln_dont_expire.

    .EXAMPLE
    Test-MtAnssiAdUserNeverExpiringPassword

    Returns $true when at most 10% of the enabled user accounts have a never-expiring password,
    $false when more do, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdUserNeverExpiringPassword
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-041',
        Title = 'No more than 10% of accounts should have a never-expiring password',
        Product = 'ad',
        Feature = 'users',
        Area = 'identity-lifecycle',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdUserNeverExpiringPassword'

    $maxPercentage = 10

    $adState = Get-MtADDomainState -Categories @('Users')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Users'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $enabledUsers = @($adState.Users | Where-Object -Property Enabled -EQ -Value $true)
    $neverExpiring = @($enabledUsers | Where-Object -Property PasswordNeverExpires -EQ -Value $true)
    Write-Verbose "Enabled users: $($enabledUsers.Count), never expiring: $($neverExpiring.Count)"

    if ($enabledUsers.Count -eq 0) {
        Add-MtTestResultDetail -Result 'No enabled user account was found in the domain.'
        return $true
    }

    $percentage = [Math]::Round(100 * $neverExpiring.Count / $enabledUsers.Count, 1)
    $summary = "$($neverExpiring.Count) of $($enabledUsers.Count) enabled user accounts " +
        "($percentage%) have a password that never expires."

    if ($neverExpiring.Count * 100 -le $enabledUsers.Count * $maxPercentage) {
        Add-MtTestResultDetail -Result "$summary The limit is $maxPercentage%."
        return $true
    }

    $oldestFirst = @($neverExpiring | Sort-Object -Property PasswordLastSet)
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $oldestFirst -Column ([ordered]@{
            'Account'           = { $_.SamAccountName }
            'Password last set' = { Format-MtAnssiAdDate $_.PasswordLastSet }
            'Last logon'        = { Format-MtAnssiAdDate $_.LastLogonDate }
        })

    $result = "$summary This is more than the $maxPercentage% limit. An attacker who " +
        "compromises one of these accounts can keep long-term access to the domain.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
