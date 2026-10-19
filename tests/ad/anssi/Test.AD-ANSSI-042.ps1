function Test-MtAnssiAdUserGuestEnabled {
    <#
    .SYNOPSIS
    ANSSI-AD-042: The Guest account should be disabled.

    .DESCRIPTION
    Reports the Guest account when it is enabled. The account is identified by its relative
    identifier 501, so a renamed Guest account is found too.

    The test is skipped when no account with relative identifier 501 is in the collected data,
    because the state of the Guest account is then unknown.

    Corresponds to the ANSSI Active Directory checkpoint vuln_guest.

    .EXAMPLE
    Test-MtAnssiAdUserGuestEnabled

    Returns $true when the Guest account is disabled, $false when it is enabled, and $null when
    the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdUserGuestEnabled
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-042',
        Title = 'The Guest account should be disabled',
        Product = 'ad',
        Feature = 'users',
        Area = 'access-control',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'T1078.001',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdUserGuestEnabled'

    $adState = Get-MtADDomainState -Categories @('Users')

    $guestAccounts = @($adState.Users | Where-Object { ([string]$_.Sid.Value) -match '-501$' })
    Write-Verbose "Accounts with relative identifier 501: $($guestAccounts.Count)"

    if ($guestAccounts.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The Guest account (relative identifier 501) was not found in the collected user data.')
        return $null
    }

    $enabledGuests = @($guestAccounts | Where-Object { $_.Enabled -eq $true })
    if ($enabledGuests.Count -eq 0) {
        Add-MtTestResultDetail -Result 'The Guest account is disabled.'
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $enabledGuests -Column ([ordered]@{
            'Account'    = { $_.SamAccountName }
            'Last logon' = { Format-MtAnssiAdDate $_.LastLogonDate }
            'SID'        = { [string]$_.Sid.Value }
        })

    $result = "The Guest account is enabled. Unauthenticated network users can log on as Guest " +
        "with no password and reach every resource that is open to it.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
