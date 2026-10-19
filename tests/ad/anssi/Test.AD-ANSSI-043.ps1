function Test-MtAnssiAdUserKerberosDesKeyOnly {
    <#
    .SYNOPSIS
    ANSSI-AD-043: User accounts should not be restricted to Kerberos DES encryption.

    .DESCRIPTION
    Reports the enabled user accounts that are restricted to the DES encryption types for
    Kerberos keys (USE_DES_KEY_ONLY, 0x200000). Disabled accounts are ignored: the key
    distribution center does not issue tickets for them.

    Corresponds to the ANSSI Active Directory checkpoint vuln_kerberos_properties_deskey.

    .EXAMPLE
    Test-MtAnssiAdUserKerberosDesKeyOnly

    Returns $true when no enabled account is restricted to DES, $false when at least one is, and
    $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdUserKerberosDesKeyOnly
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-043',
        Title = 'User accounts should not be restricted to Kerberos DES encryption',
        Product = 'ad',
        Feature = 'users',
        Area = 'authentication',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Medium',
        ImplementationCost = 'Low',
        Mitre = 'T1558',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdUserKerberosDesKeyOnly'

    $adState = Get-MtADDomainState -Categories @('Users')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Users'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $desOnly = @($adState.Users |
            Where-Object -Property Enabled -EQ -Value $true |
            Where-Object -Property UseDESKeyOnly -EQ -Value $true)
    Write-Verbose "Enabled accounts restricted to DES: $($desOnly.Count)"

    if ($desOnly.Count -eq 0) {
        $summary = 'No enabled account is restricted to Kerberos DES encryption.'
        Add-MtTestResultDetail -Result $summary
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $desOnly -Column ([ordered]@{
            'Account'           = { $_.SamAccountName }
            'Password last set' = { Format-MtAnssiAdDate $_.PasswordLastSet }
            'Last logon'        = { Format-MtAnssiAdDate $_.LastLogonDate }
        })

    $result = "Found $($desOnly.Count) enabled account(s) restricted to Kerberos DES encryption. " +
        "DES is a weak algorithm: tickets issued for these accounts are much easier to crack." +
        "`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
