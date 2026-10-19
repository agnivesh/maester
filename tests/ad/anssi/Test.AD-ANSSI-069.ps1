function Test-MtAnssiAdRodcOrphanKrbtgt {
    <#
    .SYNOPSIS
    ANSSI-AD-069: Every RODC krbtgt account should belong to a read-only domain controller.

    .DESCRIPTION
    Fails when a krbtgt_* account exists that no computer account points to through
    msDS-KrbTgtLink. Each read-only domain controller (RODC) has its own krbtgt account for the
    tickets it issues; when an RODC is removed without a clean-up of its metadata, the account
    stays behind.

    Accounts are matched by a name that starts with krbtgt_. The built-in krbtgt account has no
    suffix and is not evaluated. A domain without such an account passes.

    The test is skipped when the users or computers were not collected, or when the computers do
    not carry the attribute.

    Corresponds to the ANSSI Active Directory checkpoint vuln_rodc_orphan_krbtgt.

    .EXAMPLE
    Test-MtAnssiAdRodcOrphanKrbtgt

    Returns $true when every krbtgt_* account is linked to a computer, $false when one is not,
    and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdRodcOrphanKrbtgt
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-069',
        Title = 'Every RODC krbtgt account should belong to a read-only domain controller',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'identity-lifecycle',
        ResourceType = 'User',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdRodcOrphanKrbtgt'

    $adState = Get-MtADDomainState -Categories @('Users', 'Computers')

    $computers = @($adState.Computers)
    if (@($adState.Users).Count -eq 0 -or
        $computers[0].PSObject.Properties.Name -notcontains 'KrbTgtLink') {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The users, or the msDS-KrbTgtLink attribute of the computers, were not found in the ' +
            'collected data.')
        return $null
    }

    $accounts = @(Get-MtAnssiAdRodcKrbtgt -User $adState.Users -Computer $computers)
    $orphans = @($accounts | Where-Object { $_.IsOrphan })
    Write-Verbose "RODC krbtgt accounts: $($accounts.Count), orphans: $($orphans.Count)"

    if ($orphans.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($accounts.Count) krbtgt_* accounts belong to a read-only domain controller.")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($orphans | Sort-Object -Property Name) `
        -Column ([ordered]@{
            'Account'           = { $_.Name }
            'Enabled'           = { $_.Enabled }
            'Created'           = { Format-MtAnssiAdDate $_.Created }
            'Password last set' = { Format-MtAnssiAdDate $_.PasswordLastSet }
        })

    $result = "$($orphans.Count) of $($accounts.Count) krbtgt_* accounts are not linked to a " +
        'read-only domain controller. They are left over from RODCs that were removed and can ' +
        "be deleted after a check.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
