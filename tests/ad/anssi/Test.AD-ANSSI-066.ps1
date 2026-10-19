function Test-MtAnssiAdRodcRevealList {
    <#
    .SYNOPSIS
    ANSSI-AD-066: The reveal list of an RODC should not hold privileged accounts or groups.

    .DESCRIPTION
    Fails when the msDS-RevealOnDemandGroup list of a read-only domain controller (RODC) holds an
    account or group whose RID is lower than 1000, the range of the built-in and usually
    privileged accounts and groups. Their passwords could then be cached on the RODC. The Allowed
    RODC Password Replication Group, the default entry of the list, is accepted: ANSSI-AD-067
    checks its members.

    Entries that point outside the collected data cannot be resolved and are only counted. A
    domain without an RODC passes.

    The test is skipped when the domain SID, the computers or their RODC attributes are not in the
    collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_rodc_reveal.

    .EXAMPLE
    Test-MtAnssiAdRodcRevealList

    Returns $true when no RODC may cache a privileged account, $false when one may, and $null
    when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdRodcRevealList
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-066',
        Title = 'The reveal list of an RODC should not hold privileged accounts or groups',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'privileged-access',
        ResourceType = 'DomainController',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'T1003',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdRodcRevealList'

    $adState = Get-MtADDomainState -Categories @(
        'Domain', 'Users', 'Computers', 'Groups', 'DomainControllers')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    $computers = @($adState.Computers)
    $hasAttribute = $computers[0].PSObject.Properties.Name -contains 'RevealOnDemandGroup'
    if (-not $domainSid -or -not $hasAttribute) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID, or the RODC attributes of the computers, were not found in the ' +
            'collected data.')
        return $null
    }

    $rodcs = @(Get-MtAnssiAdDomainController -Computer $computers `
            -DomainController $adState.DomainControllers | Where-Object { $_.Type -eq 'ReadOnly' })
    if ($rodcs.Count -eq 0) {
        Add-MtTestResultDetail -Result 'The domain has no read-only domain controller.'
        return $true
    }

    $lookup = Get-MtAnssiAdSidByDn -User $adState.Users -Computer $computers -Group $adState.Groups
    $rows = @(Get-MtAnssiAdRodcRevealRisk -Controller $rodcs -Lookup $lookup -DomainSid $domainSid)
    $findings = @($rows | Where-Object { @($_.Risky).Count -gt 0 })
    $unresolved = ($rows | Measure-Object -Property Unresolved -Sum).Sum
    $note = ''
    if ($unresolved -gt 0) {
        $note = " $unresolved entries point outside the collected data and were not evaluated."
    }
    Write-Verbose "RODCs: $($rodcs.Count), with a privileged reveal entry: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "The reveal lists of all $($rodcs.Count) read-only domain controllers hold no " +
            "account or group with a RID below 1000.$note")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property Name) `
        -Column ([ordered]@{
            'Read-only domain controller' = { $_.Name }
            'Privileged entries'          = { @($_.Risky) -join ', ' }
        })

    $result = "$($findings.Count) of $($rodcs.Count) read-only domain controllers may cache the " +
        "password of a built-in, usually privileged, account or group.$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
