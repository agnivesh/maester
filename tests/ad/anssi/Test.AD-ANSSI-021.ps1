function Test-MtAnssiAdPrivilegedStalePassword {
    <#
    .SYNOPSIS
    ANSSI-AD-021: Privileged accounts should change their password at least every 3 years.

    .DESCRIPTION
    Fails when an enabled privileged user account has not changed its password for more than
    3 years, or has no password change date. The built-in Administrator account counts. A
    privileged account is a member, direct, nested or through its primary group, of a group that
    Active Directory protects with AdminSDHolder, or the built-in Administrator or krbtgt account.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when the members of a protected group cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_password_change_priv.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedStalePassword

    Returns $true when every enabled privileged user account changed its password in the last
    3 years, $false when one did not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedStalePassword
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-021',
        Title = 'Privileged accounts should change their password at least every 3 years',
        Product = 'ad',
        Feature = 'account-security',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1078.002',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedStalePassword'

    $cutoff = (Get-Date).ToUniversalTime().AddYears(-3)

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID was not found in the collected data.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence

    $users = @($privileged.Account |
        Where-Object { $_.Kind -eq 'User' -and $_.Item.Enabled -eq $true })
    $findings = @($users | Where-Object { $_.Item.PasswordLastSet -lt $cutoff })
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Enabled privileged users: $($users.Count), stale password: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("All $($users.Count) enabled privileged user accounts " +
            "changed their password in the last 3 years.$note")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property { $_.Item.PasswordLastSet }) `
        -Column ([ordered]@{
            'Account'            = { $_.Item.SamAccountName }
            'Password last set'  = { Format-MtAnssiAdDate $_.Item.PasswordLastSet }
            'Privileged through' = { $_.Group -join ', ' }
            'Last logon'         = { Format-MtAnssiAdDate $_.Item.LastLogonDate }
        })

    $result = "$($findings.Count) of $($users.Count) enabled privileged user accounts have not " +
        "changed their password in the last 3 years (before $(Format-MtAnssiAdDate $cutoff))." +
        "$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
