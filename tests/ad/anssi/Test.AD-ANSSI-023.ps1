function Test-MtAnssiAdDcPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-023: Only privileged principals should control domain controller objects.

    .DESCRIPTION
    Reads the owner and permissions of every domain controller computer object, writable and
    read-only, and fails when a principal that is not privileged owns one or holds a right that
    gives control over it (full control, changing its permissions or owner, writing its
    attributes). On a read-only domain controller, a manager that is not privileged is reported
    too, since it is a local administrator of the controller, and the right to change the manager
    counts as level 1. Rights usable without a major prerequisite are level 1 (Critical), other
    potentially dangerous rights level 2 (High); the most severe level found is reported.

    The test is skipped when the domain SID is not in the collected data, when no domain
    controller is found, when a protected group is missing, when a read fails, or when the
    permissions of a controller object cannot be read.

    .EXAMPLE
    Test-MtAnssiAdDcPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on a domain
    controller object, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDcPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-023',
        Title = 'Only privileged principals should control domain controller objects',
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

    Write-Verbose 'Starting Test-MtAnssiAdDcPermission'

    $adState = Get-MtADDomainState -Categories @(
        'Domain', 'Users', 'Computers', 'Groups', 'DomainControllers')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    $controllers = @(Get-MtAnssiAdDomainController -Computer $adState.Computers `
            -DomainController $adState.DomainControllers)
    if (-not $domainSid -or $controllers.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID or the domain controller computer accounts were not found in the ' +
            'collected data.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $trusted = Get-MtAnssiAdTrustedSid -Privileged $privileged -Group $adState.Groups `
        -DomainSid $domainSid
    $objects = @(Get-MtAnssiAdObjectSecurity -ProtocolEvidence $adState.ProtocolEvidence `
            -DistinguishedName @($controllers.Computer.DistinguishedName))

    $unreadable = @($objects | Where-Object { $null -eq $_.Ace })
    if ($unreadable.Count -gt 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            "The permissions of $($unreadable.Count) domain controller objects could not be read.")
        return $null
    }

    $lookup = Get-MtAnssiAdSidByDn -User $adState.Users -Computer $adState.Computers `
        -Group $adState.Groups
    $rows = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted)
    $findings = @(Get-MtAnssiAdRodcControl -Controller $controllers -Row $rows -Lookup $lookup `
            -TrustedSid $trusted)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Dangerous rights on domain controller objects: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2) -Result (
            "No principal outside the privileged set holds a dangerous right on the " +
            "$($controllers.Count) domain controller objects.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) dangerous rights on domain controller objects are held by " +
        "principals outside the privileged set.$note`n`n$table"

    $severity = Get-MtAnssiAdSeverity -Grade @($findings.Level)
    Add-MtTestResultDetail -Severity $severity -Result $result
    return $false
}
