function Test-MtAnssiAdRodcNeverRevealList {
    <#
    .SYNOPSIS
    ANSSI-AD-065: Each RODC never-reveal list should hold the default privileged groups.

    .DESCRIPTION
    Fails when the msDS-NeverRevealGroup list of a read-only domain controller (RODC) lacks one of
    Administrators, Server Operators, Account Operators, Backup Operators or the Denied RODC
    Password Replication Group. Accounts of those groups could then have their secrets cached on
    the RODC, where they are exposed if the RODC is compromised.

    Only direct entries of the list count. A domain without an RODC passes.

    The test is skipped when the domain SID, the computers or their RODC attributes are not in the
    collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_rodc_never_reveal.

    .EXAMPLE
    Test-MtAnssiAdRodcNeverRevealList

    Returns $true when every RODC lists all the groups, $false when one does not, and $null when
    the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdRodcNeverRevealList
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-065',
        Title = 'Each RODC never-reveal list should hold the default privileged groups',
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

    Write-Verbose 'Starting Test-MtAnssiAdRodcNeverRevealList'

    $adState = Get-MtADDomainState -Categories @(
        'Domain', 'Computers', 'Groups', 'DomainControllers')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    $computers = @($adState.Computers)
    $hasAttribute = $computers[0].PSObject.Properties.Name -contains 'NeverRevealGroup'
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

    $lookup = Get-MtAnssiAdSidByDn -Group $adState.Groups
    $gaps = @(Get-MtAnssiAdRodcNeverRevealGap -Controller $rodcs -Lookup $lookup `
            -DomainSid $domainSid)
    Write-Verbose "RODCs: $($rodcs.Count), with an incomplete never-reveal list: $($gaps.Count)"

    if ($gaps.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "The never-reveal lists of all $($rodcs.Count) read-only domain controllers hold " +
            'the default privileged groups.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject @($gaps | Sort-Object -Property Name) `
        -Column ([ordered]@{
            'Read-only domain controller' = { $_.Name }
            'Missing from the list'       = { @($_.Missing) -join ', ' }
        })

    $result = "$($gaps.Count) of $($rodcs.Count) read-only domain controllers do not deny " +
        'secret caching to all the default privileged groups. Members of a missing group can ' +
        "have their password cached on the RODC.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
