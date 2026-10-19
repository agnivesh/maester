function Test-MtAnssiAdPrivilegedKerberosPreauthDisabled {
    <#
    .SYNOPSIS
    ANSSI-AD-018: Privileged accounts should require Kerberos preauthentication.

    .DESCRIPTION
    Fails when an enabled privileged user account has DONT_REQ_PREAUTH (0x400000) set. A
    privileged account is a member, direct, nested or through its primary group, of a group that
    Active Directory protects with AdminSDHolder, or the built-in Administrator or krbtgt account.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when the members of a protected group cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_kerberos_properties_preauth_priv.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedKerberosPreauthDisabled

    Returns $true when every enabled privileged user account requires preauthentication, $false
    when one does not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedKerberosPreauthDisabled
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-018',
        Title = 'Privileged accounts should require Kerberos preauthentication',
        Product = 'ad',
        Feature = 'account-security',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'T1558.004',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedKerberosPreauthDisabled'

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
    $findings = @($users | Where-Object { $_.Item.DoesNotRequirePreAuth -eq $true })
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose ("Enabled privileged users: $($users.Count), without preauthentication: " +
        "$($findings.Count)")

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("All $($users.Count) enabled privileged user accounts " +
            "require Kerberos preauthentication.$note")
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

    $result = "$($findings.Count) of $($users.Count) enabled privileged user accounts do not " +
        "require Kerberos preauthentication. Anyone can request a ticket for them and try to " +
        "crack their password offline.$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
