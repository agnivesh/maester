function Test-MtAnssiAdDnsAdminsGroup {
    <#
    .SYNOPSIS
    ANSSI-AD-013: DnsAdmins should be empty and controlled only by privileged principals.

    .DESCRIPTION
    Finds the DnsAdmins group by name and fails when it has any member (direct, nested or through
    the primary group), or when a principal that is not privileged owns it or holds a right that
    gives control over it, such as changing its members, its permissions or its owner. Members of
    DnsAdmins manage the DNS service, which usually runs on the domain controllers, and depending
    on patches and settings can make it run their code there. A domain without a DnsAdmins group
    passes.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, when a read fails, or when the permissions of DnsAdmins cannot be read.

    .EXAMPLE
    Test-MtAnssiAdDnsAdminsGroup

    Returns $true when DnsAdmins is empty and controlled only by privileged principals, $false
    otherwise, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDnsAdminsGroup
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-013',
        Title = 'DnsAdmins should be empty and controlled only by privileged principals',
        Product = 'ad',
        Feature = 'dns',
        Area = 'privileged-access',
        ResourceType = 'Group',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDnsAdminsGroup'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Users', 'Computers', 'Groups'
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

    $group = @($adState.Groups | Where-Object { $_.SamAccountName -eq 'DnsAdmins' })[0]
    if ($null -eq $group) {
        Add-MtTestResultDetail -Result 'The domain has no group named DnsAdmins.'
        return $true
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $trusted = Get-MtAnssiAdTrustedSid -Privileged $privileged -Group $adState.Groups `
        -DomainSid $domainSid
    $membership = Get-MtAnssiAdGroupMemberAccount -AdState $adState -GroupSid $group.Sid.Value
    $target = @(Get-MtAnssiAdObjectSecurity -ProtocolEvidence $adState.ProtocolEvidence `
            -DistinguishedName $group.DistinguishedName)

    if ($null -eq $target[0].Ace) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The permissions of the DnsAdmins group could not be read.')
        return $null
    }

    $members = @(ConvertTo-MtAnssiAdGroupMemberRow -Membership $membership)
    $rights = @(Get-MtAnssiAdAceControl -Object $target -TrustedSid $trusted)
    $rights | ForEach-Object { $_.Level = 1 }
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "DnsAdmins members: $($members.Count), dangerous rights: $($rights.Count)"

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $report = Get-MtAnssiAdDnsAdminsReport -Member $members -Right $rights `
        -Principal $principal -Note $note
    Add-MtTestResultDetail -Result $report.Result
    return $report.Passed
}
