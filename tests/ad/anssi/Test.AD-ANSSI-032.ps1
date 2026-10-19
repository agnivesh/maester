function Test-MtAnssiAdPrivilegedMemberCount {
    <#
    .SYNOPSIS
    ANSSI-AD-032: The domain should not have too many privileged accounts.

    .DESCRIPTION
    Counts the accounts that are members, directly, through nesting or through their primary
    group, of the groups Active Directory protects with AdminSDHolder, each account once, and
    fails when there are more than 50, or more than 3 per domain of the forest when that is
    higher. The built-in Administrator account and the domain controller accounts do not count.

    The test is skipped when the domain SID or the number of domains in the forest is not in the
    collected data, when a protected group is missing, or when a group cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_privileged_members.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedMemberCount

    Returns $true when the number of privileged accounts is within the limit, $false when it is
    above, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedMemberCount
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-032',
        Title = 'The domain should not have too many privileged accounts',
        Product = 'ad',
        Feature = 'groups',
        Area = 'privileged-access',
        ResourceType = 'Group',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedMemberCount'

    $adState = Get-MtADDomainState -Categories @(
        'Domain', 'Users', 'Computers', 'Groups', 'DomainControllers')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    $domainCount = $adState.Domain.ForestDomainCount
    if (-not $domainSid -or $null -eq $domainCount) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID, or the number of domains in the forest, was not found in the ' +
            'collected data.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence

    $controllers = @(Get-MtAnssiAdDomainController -Computer $adState.Computers `
            -DomainController $adState.DomainControllers)
    $counted = @(Select-MtAnssiAdCountedPrivilegedAccount -Account $privileged.Account `
            -DomainController $controllers -DomainSid $domainSid)
    $limit = [Math]::Max(50, 3 * $domainCount)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    $summary = "The domain has $($counted.Count) privileged account(s). The limit is $limit " +
        "(50, or 3 per domain of the $domainCount-domain forest when that is higher)."
    Write-Verbose $summary

    if ($counted.Count -le $limit) {
        Add-MtTestResultDetail -Result "$summary$note"
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($counted | Sort-Object -Property { $_.Item.SamAccountName }) `
        -Column ([ordered]@{
            'Account'            = { $_.Item.SamAccountName }
            'Type'               = { $_.Kind }
            'Enabled'            = { $_.Item.Enabled }
            'Privileged through' = { $_.Group -join ', ' }
        })

    $result = "$summary That is too many to keep track of: review who really needs these " +
        "rights.$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
