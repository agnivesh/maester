function Test-MtAnssiAdUserKerberosPreauthDisabled {
    <#
    .SYNOPSIS
    ANSSI-AD-044: Kerberos preauthentication should be required for enabled accounts.

    .DESCRIPTION
    Reports the enabled user accounts that do not require Kerberos preauthentication
    (DONT_REQ_PREAUTH, 0x400000). Disabled accounts are ignored: the key distribution center does
    not answer for them.

    Corresponds to the ANSSI Active Directory checkpoint vuln_kerberos_properties_preauth.

    .EXAMPLE
    Test-MtAnssiAdUserKerberosPreauthDisabled

    Returns $true when every enabled account requires preauthentication, $false when at least one
    does not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdUserKerberosPreauthDisabled
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-044',
        Title = 'Kerberos preauthentication should be required for enabled accounts',
        Product = 'ad',
        Feature = 'users',
        Area = 'authentication',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1558.004',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdUserKerberosPreauthDisabled'

    $adState = Get-MtADDomainState -Categories @('Users')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Users'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $withoutPreauth = @($adState.Users |
            Where-Object -Property Enabled -EQ -Value $true |
            Where-Object -Property DoesNotRequirePreAuth -EQ -Value $true)
    Write-Verbose "Enabled accounts without preauthentication: $($withoutPreauth.Count)"

    if ($withoutPreauth.Count -eq 0) {
        Add-MtTestResultDetail -Result 'No enabled account has Kerberos preauthentication disabled.'
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $withoutPreauth -Column ([ordered]@{
            'Account'           = { $_.SamAccountName }
            'Password last set' = { Format-MtAnssiAdDate $_.PasswordLastSet }
            'Last logon'        = { Format-MtAnssiAdDate $_.LastLogonDate }
        })

    $result = "Found $($withoutPreauth.Count) enabled account(s) with Kerberos preauthentication " +
        "disabled. An attacker can request a ticket encrypted with the key of these accounts " +
        "without knowing their password, then try to crack the password offline.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
