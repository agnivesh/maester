function Test-MtAnssiAdRodcRevealedPrivilegedAccount {
    <#
    .SYNOPSIS
    ANSSI-AD-052: No privileged account should have its secrets cached on an RODC.

    .DESCRIPTION
    Fails when a privileged account, user or computer, enabled or not, is listed in the
    msDS-RevealedUsers attribute of a read-only domain controller (RODC), which means that its
    password secrets are cached there. Anyone who takes over that RODC can then take over the
    account. A privileged account is a member, direct, nested or through its primary group, of a
    group that Active Directory protects with AdminSDHolder, or the built-in Administrator or
    krbtgt account. A domain without an RODC passes.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when a read fails.

    Corresponds to the ANSSI Active Directory checkpoint vuln_rodc_priv_revealed.

    .EXAMPLE
    Test-MtAnssiAdRodcRevealedPrivilegedAccount

    Returns $true when no privileged account is cached on an RODC, $false when one is, and $null
    when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdRodcRevealedPrivilegedAccount
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-052',
        Title = 'No privileged account should have its secrets cached on an RODC',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1003',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdRodcRevealedPrivilegedAccount'

    $adState = Get-MtADDomainState -Categories @(
        'Domain', 'Users', 'Computers', 'Groups', 'DomainControllers')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState `
        -Name 'Users', 'Computers', 'Groups', 'DomainControllers'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID was not found in the collected data.')
        return $null
    }

    $rodcs = @(Get-MtAnssiAdDomainController -Computer $adState.Computers `
            -DomainController $adState.DomainControllers | Where-Object { $_.Type -eq 'ReadOnly' })
    if ($rodcs.Count -eq 0) {
        Add-MtTestResultDetail -Result 'The domain has no read-only domain controller.'
        return $true
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $findings = @(Get-MtAnssiAdRodcRevealedAccount -Controller $rodcs `
            -Account $privileged.Account -ProtocolEvidence $adState.ProtocolEvidence)

    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "RODCs: $($rodcs.Count), privileged accounts cached on one: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("None of the $(@($privileged.Account).Count) privileged " +
            "accounts is cached on the $($rodcs.Count) read-only domain controller(s).$note")
        return $true
    }

    $table = Format-MtAnssiAdRodcRevealedTable -Finding $findings

    $result = "$($findings.Count) privileged account secret(s) are cached on read-only domain " +
        "controllers. Change the password of each of these accounts.$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
