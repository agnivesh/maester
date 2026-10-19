function Test-MtAnssiAdDfsrSysvolPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-024: Only privileged principals should control the SYSVOL DFSR settings.

    .DESCRIPTION
    Reads the owner and permissions of the DFS Replication objects that replicate SYSVOL: the
    Domain System Volume replication group and everything below it, and the DFSR settings below
    each domain controller account. Fails when a principal that is not privileged owns one or
    holds a right that gives control over it, such as adding a member to the replication group,
    changing a subscription, or changing permissions or owner. Such a principal can make its own
    copy of SYSVOL replicate to every domain controller, with the scripts and group policies in it.
    Rights usable without a major prerequisite are level 1 (Critical), other potentially
    dangerous rights level 2 (High); the most severe level found is reported. A domain that does
    not replicate SYSVOL with DFSR has no such objects, so the test is skipped for it.

    The test is skipped when the domain SID or name is not in the collected data, when a protected
    group is missing, when a read fails, when no DFSR object is visible (the account may lack read
    access), or when the permissions of an object cannot be read.

    .EXAMPLE
    Test-MtAnssiAdDfsrSysvolPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on a SYSVOL
    DFSR object, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDfsrSysvolPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-024',
        Title = 'Only privileged principals should control the SYSVOL DFSR settings',
        Product = 'ad',
        Feature = 'permissions',
        Area = 'infrastructure',
        ResourceType = 'Permission',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1484.001',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDfsrSysvolPermission'

    $adState = Get-MtADDomainState -Categories @(
        'Domain', 'Users', 'Computers', 'Groups', 'DomainControllers')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    $domainDn = [string]$adState.Domain.DistinguishedName
    if (-not $domainSid -or -not $domainDn) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID or name was not found in the collected data.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $trusted = Get-MtAnssiAdTrustedSid -Privileged $privileged -Group $adState.Groups `
        -DomainSid $domainSid
    $objects = @(Get-MtAnssiAdDfsrSysvolObject -DomainDn $domainDn `
            -Computer $adState.Computers -DomainController $adState.DomainControllers `
            -ProtocolEvidence $adState.ProtocolEvidence)

    $readable = @($objects | Where-Object { $null -ne $_.Ace }).Count
    if ($readable -ne [Math]::Max($objects.Count, 1)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No SYSVOL DFSR object is visible to the account that reads the directory, or the ' +
            'permissions of one could not be read.')
        return $null
    }

    $findings = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted)
    $findings | ForEach-Object { $_.Name = $_.DistinguishedName }
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2) -Result (
            'No principal outside the privileged set holds a dangerous right on the ' +
            "$($objects.Count) SYSVOL DFSR objects.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) dangerous rights on SYSVOL DFSR objects are held by " +
        "principals outside the privileged set.$note`n`n$table"
    Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade @($findings.Level)) `
        -Result $result
    return $false
}
