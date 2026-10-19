function Test-MtAnssiAdManagedServiceAccountStalePassword {
    <#
    .SYNOPSIS
    ANSSI-AD-048: Managed service accounts should have changed their password within 90 days.

    .DESCRIPTION
    Fails when an enabled group managed service account (gMSA) or standalone managed service
    account (MSA) has a password older than 90 days, or no password date at all. Windows rotates
    these passwords on its own, every 30 days by default, so an old password means the rotation
    has stopped, which needs an explanation.

    Disabled accounts are not evaluated. Delegated managed service accounts (dMSA) handle their
    secret differently and are not evaluated either. A gMSA created with a rotation interval
    longer than 90 days is reported even though it behaves as configured.

    The test is skipped when the computers, which include the managed service accounts, were not
    collected or do not carry their object classes.

    Corresponds to the ANSSI Active Directory checkpoint vuln_password_change_msa_no_change_90.

    .EXAMPLE
    Test-MtAnssiAdManagedServiceAccountStalePassword

    Returns $true when every enabled managed service account changed its password within 90 days,
    $false when one did not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdManagedServiceAccountStalePassword
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-048',
        Title = 'Managed service accounts should have changed their password within 90 days',
        Product = 'ad',
        Feature = 'account-security',
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

    Write-Verbose 'Starting Test-MtAnssiAdManagedServiceAccountStalePassword'

    $maxAgeDays = 90
    $now = (Get-Date).ToUniversalTime()

    $adState = Get-MtADDomainState -Categories @('Computers')

    $computers = @($adState.Computers)
    if ($computers[0].PSObject.Properties.Name -notcontains 'ObjectClass') {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The computers, or their object classes, were not found in the collected data.')
        return $null
    }

    $accounts = @(Get-MtAnssiAdManagedServiceAccount -Computer $computers)
    $found = Get-MtAnssiAdStaleComputer -Computer $accounts `
        -Attribute PasswordLastSet -Cutoff $now.AddDays(-$maxAgeDays) -NullIsStale
    Write-Verbose ("Enabled managed service accounts: $($found.EnabledCount), " +
        "stale: $($found.Stale.Count)")

    if ($found.EnabledCount -eq 0) {
        Add-MtTestResultDetail -Result 'The domain has no enabled managed service account.'
        return $true
    }

    if ($found.Stale.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($found.EnabledCount) enabled managed service accounts changed their password " +
            "within the last $maxAgeDays days.")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($found.Stale | Sort-Object -Property Date, { $_.Computer.Name }) `
        -DomainSource { $_.Computer.DistinguishedName } `
        -Column ([ordered]@{
            'Account'           = { $_.Computer.Name }
            'Type'              = { $_.Computer.Type }
            'Password last set' = { Format-MtAnssiAdDate $_.Date }
            'Last logon'        = { Format-MtAnssiAdDate $_.Computer.LastLogonDate }
        })

    $result = "$($found.Stale.Count) of $($found.EnabledCount) enabled managed service accounts " +
        "have not changed their password for more than $maxAgeDays days. Their automatic " +
        "rotation has stopped; find out why.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
