function Test-MtAnssiAdPrivilegedReversiblePassword {
    <#
    .SYNOPSIS
    ANSSI-AD-063: Privileged accounts should not store passwords with reversible encryption.

    .DESCRIPTION
    Fails when a privileged user account has ENCRYPTED_TEXT_PWD_ALLOWED (0x80) set, enabled or
    not: the password stored for it can be turned back into clear text. A privileged account is a
    member, direct, nested or through its primary group, of a group that Active Directory protects
    with AdminSDHolder, or the built-in Administrator or krbtgt account.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when the members of a protected group cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_reversible_password_priv_uac.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedReversiblePassword

    Returns $true when no privileged user account stores its password with reversible
    encryption, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedReversiblePassword
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-063',
        Title = 'Privileged accounts should not store passwords with reversible encryption',
        Product = 'ad',
        Feature = 'account-security',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1003.006',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedReversiblePassword'

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

    $users = @($privileged.Account | Where-Object { $_.Kind -eq 'User' })
    $findings = @($users | Where-Object { ($_.Item.UserAccountControl -band 0x80) -ne 0 })
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Privileged users: $($users.Count), reversible encryption: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("None of the $($users.Count) privileged user accounts " +
            "stores its password with reversible encryption.$note")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property { $_.Item.SamAccountName }) `
        -Column ([ordered]@{
            'Account'            = { $_.Item.SamAccountName }
            'Enabled'            = { $_.Item.Enabled }
            'Privileged through' = { $_.Group -join ', ' }
            'Password last set'  = { Format-MtAnssiAdDate $_.Item.PasswordLastSet }
        })

    $result = "$($findings.Count) of $($users.Count) privileged user accounts store their " +
        'password with reversible encryption. Anyone who can read the domain secrets, for ' +
        "example from a domain controller backup, can recover these passwords in clear text.$note" +
        "`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
