function Test-MtAnssiAdRodcAllowedGroupEmpty {
    <#
    .SYNOPSIS
    ANSSI-AD-067: The Allowed RODC Password Replication Group should be empty.

    .DESCRIPTION
    Fails when the Allowed RODC Password Replication Group (domain RID 571) has members. The
    group is in the reveal list of every read-only domain controller (RODC) by default, so the
    passwords of its members can be cached on all of them. Branch accounts should instead be
    allowed through dedicated groups on the RODCs that need them.

    Only direct members are read. The test is skipped when the domain SID or the group is not in
    the collected data, or when the members cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_rodc_allowed_group.

    .EXAMPLE
    Test-MtAnssiAdRodcAllowedGroupEmpty

    Returns $true when the group is empty, $false when it has members, and $null when the test is
    skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdRodcAllowedGroupEmpty
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-067',
        Title = 'The Allowed RODC Password Replication Group should be empty',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'infrastructure',
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

    Write-Verbose 'Starting Test-MtAnssiAdRodcAllowedGroupEmpty'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    $members = $null
    if ($domainSid) {
        $members = Get-MtAnssiAdGroupMemberDn -Group $adState.Groups -Sid "$domainSid-571" `
            -ProtocolEvidence $adState.ProtocolEvidence
    }

    if ($null -eq $members) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID or the Allowed RODC Password Replication Group was not found in the ' +
            'collected data.')
        return $null
    }

    $memberDn = @($members.Member)
    Write-Verbose "Allowed RODC Password Replication Group members: $($memberDn.Count)"
    if ($memberDn.Count -eq 0) {
        Add-MtTestResultDetail -Result 'The Allowed RODC Password Replication Group is empty.'
        return $true
    }

    $lookup = Get-MtAnssiAdSidByDn -User $adState.Users -Computer $adState.Computers `
        -Group $adState.Groups
    $resolved = @(Resolve-MtAnssiAdSid -DistinguishedName $memberDn -Lookup $lookup)
    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($resolved | Sort-Object -Property Name) `
        -Column ([ordered]@{
            'Member' = { $_.Name }
            'SID'    = { $_.Sid }
        })

    $result = "The Allowed RODC Password Replication Group has $($memberDn.Count) member(s). " +
        'Their passwords can be cached on every read-only domain controller of the domain.' +
        "`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
