function Test-MtAnssiAdPrivilegedNeverExpiringPassword {
    <#
    .SYNOPSIS
    ANSSI-AD-015: Privileged accounts should not have a password that never expires.

    .DESCRIPTION
    Fails when an enabled privileged user account has DONT_EXPIRE_PASSWORD (0x10000) set. A
    privileged account is a member, direct, nested or through its primary group, of a group that
    Active Directory protects with AdminSDHolder, or the built-in Administrator or krbtgt account.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when the members of a protected group cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_dont_expire_priv.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedNeverExpiringPassword

    Returns $true when no enabled privileged user account has a never-expiring password, $false
    when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedNeverExpiringPassword
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-015',
        Title = 'Privileged accounts should not have a password that never expires',
        Product = 'ad',
        Feature = 'account-security',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1078.002',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedNeverExpiringPassword'

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
    $findings = @($users | Where-Object { $_.Item.PasswordNeverExpires -eq $true })
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Enabled privileged users: $($users.Count), never expiring: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("None of the $($users.Count) enabled privileged user " +
            "accounts has a password that never expires.$note")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property { $_.Item.PasswordLastSet }) `
        -Column ([ordered]@{
            'Account'            = { $_.Item.SamAccountName }
            'Privileged through' = { $_.Group -join ', ' }
            'Password last set'  = { Format-MtAnssiAdDate $_.Item.PasswordLastSet }
            'Last logon'         = { Format-MtAnssiAdDate $_.Item.LastLogonDate }
        })

    $result = "$($findings.Count) of $($users.Count) enabled privileged user accounts have a " +
        "password that never expires.$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
