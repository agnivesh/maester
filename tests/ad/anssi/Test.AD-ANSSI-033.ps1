function Test-MtAnssiAdPrivilegedMemberPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-033: Only privileged principals should control privileged accounts and groups.

    .DESCRIPTION
    Reads the owner and permissions of every privileged account (user or computer) and of every
    group that leads to a protected group, and fails when a principal that is not privileged owns
    one or holds a right that gives control over it, such as resetting a password, changing the
    members of a group, or changing permissions or owner. Most of these objects take their
    permissions from AdminSDHolder, so many findings repeat those of the AdminSDHolder test; the
    others, such as domain controllers, are privileged through their primary group only. Rights
    usable without a major prerequisite are level 1 (Critical), other potentially dangerous rights
    level 2 (High); the most severe level found is reported.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, when a read fails, when no privileged object is visible (the account may lack read
    access), or when the permissions of an object cannot be read.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedMemberPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on a
    privileged account or group, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedMemberPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-033',
        Title = 'Only privileged principals should control privileged accounts and groups',
        Product = 'ad',
        Feature = 'permissions',
        Area = 'privileged-access',
        ResourceType = 'Permission',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1098',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedMemberPermission'

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
    $trusted = Get-MtAnssiAdTrustedSid -Privileged $privileged -Group $adState.Groups `
        -DomainSid $domainSid
    $target = @($privileged.Account.DistinguishedName) + @($privileged.Group)
    $objects = @(Get-MtAnssiAdObjectSecurity -ProtocolEvidence $adState.ProtocolEvidence `
            -DistinguishedName $target)

    $readable = @($objects | Where-Object { $null -ne $_.Ace }).Count
    if ($readable -ne [Math]::Max($objects.Count, 1)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            "No privileged account or group is visible, or the permissions of " +
            "$($objects.Count - $readable) of them could not be read.")
        return $null
    }

    $findings = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Privileged objects: $($objects.Count), dangerous rights: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2) -Result (
            'No principal outside the privileged set holds a dangerous right on the ' +
            "$($objects.Count) privileged accounts and groups.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) dangerous rights on privileged accounts and groups are held " +
        "by principals outside the privileged set.$note`n`n$table"

    $severity = Get-MtAnssiAdSeverity -Grade @($findings.Level)
    Add-MtTestResultDetail -Severity $severity -Result $result
    return $false
}
