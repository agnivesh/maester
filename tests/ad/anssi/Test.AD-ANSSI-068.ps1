function Test-MtAnssiAdRodcDeniedGroupMember {
    <#
    .SYNOPSIS
    ANSSI-AD-068: The Denied RODC Password Replication Group should keep its default members.

    .DESCRIPTION
    Fails when the Denied RODC Password Replication Group (domain RID 572) lacks one of its
    default members: Domain Controllers, Read-only Domain Controllers, Group Policy Creator
    Owners, Domain Admins, Cert Publishers and the krbtgt account, plus Schema Admins and
    Enterprise Admins in the forest root domain. Every read-only domain controller (RODC) refuses
    to cache the passwords of this group's members, so a missing member loses that protection.

    Only direct members count. In a domain other than the forest root, Schema Admins and
    Enterprise Admins belong to the root domain and are not checked.

    The test is skipped when the domain or the group is not in the collected data, or when the
    members cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_rodc_denied_group.

    .EXAMPLE
    Test-MtAnssiAdRodcDeniedGroupMember

    Returns $true when the group holds all its default members, $false when one is missing, and
    $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdRodcDeniedGroupMember
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-068',
        Title = 'The Denied RODC Password Replication Group should keep its default members',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'privileged-access',
        ResourceType = 'Group',
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

    Write-Verbose 'Starting Test-MtAnssiAdRodcDeniedGroupMember'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Groups')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    $members = $null
    if ($domainSid) {
        $members = Get-MtAnssiAdGroupMemberDn -Group $adState.Groups -Sid "$domainSid-572" `
            -ProtocolEvidence $adState.ProtocolEvidence
    }

    if ($null -eq $members) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID or the Denied RODC Password Replication Group was not found in the ' +
            'collected data.')
        return $null
    }

    $isRoot = [string]$adState.Domain.DnsRoot -eq [string]$adState.Domain.Forest
    $lookup = Get-MtAnssiAdSidByDn -User $adState.Users -Group $adState.Groups
    $memberSid = @(Resolve-MtAnssiAdSid -DistinguishedName $members.Member -Lookup $lookup |
            ForEach-Object { $_.Sid })
    $missing = @(Get-MtAnssiAdDeniedGroupGap -MemberSid $memberSid -DomainSid $domainSid `
            -IsForestRoot:$isRoot)
    Write-Verbose "Missing default members: $($missing.Count), forest root: $isRoot"

    $scope = ''
    if (-not $isRoot) {
        $scope = ' Schema Admins and Enterprise Admins belong to the forest root domain and were ' +
            'not checked.'
    }

    if ($missing.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "The Denied RODC Password Replication Group holds all its default members.$scope")
        return $true
    }

    $names = Get-MtSafeMarkdown ($missing -join ', ')
    Add-MtTestResultDetail -Result (
        'The Denied RODC Password Replication Group is missing default members: ' +
        "$names. Read-only domain controllers may cache their passwords.$scope")
    return $false
}
