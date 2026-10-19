function Test-MtAnssiAdNamingContextPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-027: Only privileged principals should control the naming context roots.

    .DESCRIPTION
    Reads the owner and permissions of the root of the domain, Configuration and Schema naming
    contexts and of the DomainDnsZones and ForestDnsZones partitions, and fails when a principal
    that is not privileged owns one or holds a right that gives control over it, such as full
    control, changing its permissions or owner, writing its attributes or replicating its secrets
    (DCSync). Rights usable without a major prerequisite are level 1 (Critical), other
    potentially dangerous rights level 2 (High); the most severe level found is reported.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, when a read fails, when no root is visible (the account may lack read access), or
    when the permissions of a root cannot be read.

    .EXAMPLE
    Test-MtAnssiAdNamingContextPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on a
    naming context root, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdNamingContextPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-027',
        Title = 'Only privileged principals should control the naming context roots',
        Product = 'ad',
        Feature = 'permissions',
        Area = 'privileged-access',
        ResourceType = 'Permission',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1003.006',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdNamingContextPermission'

    $adState = Get-MtADDomainState `
        -Categories @('Domain', 'Users', 'Computers', 'Groups', 'Trusts')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID was not found in the collected data.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $rootSid = Get-MtAnssiAdForestRootSid -Domain $adState.Domain -Trust $adState.Trusts
    $trusted = Get-MtAnssiAdTrustedSid -Privileged $privileged -Group $adState.Groups `
        -DomainSid $domainSid -ForestRootSid $rootSid
    $head = @(Get-MtAnssiAdNamingContextHead -ProtocolEvidence $adState.ProtocolEvidence)
    $objects = @(Get-MtAnssiAdObjectSecurity -ProtocolEvidence $adState.ProtocolEvidence `
            -DistinguishedName $head)

    $readable = @($objects | Where-Object { $null -ne $_.Ace }).Count
    if ($readable -ne [Math]::Max($objects.Count, 1)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            "No naming context root is visible, or the permissions of " +
            "$($objects.Count - $readable) of them could not be read.")
        return $null
    }

    $findings = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Dangerous rights on naming context roots: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2) -Result (
            'No principal outside the privileged set holds a dangerous right on the ' +
            "$($objects.Count) naming context roots.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) dangerous rights on naming context roots are held by " +
        "principals outside the privileged set.$note`n`n$table"

    $severity = Get-MtAnssiAdSeverity -Grade @($findings.Level)
    Add-MtTestResultDetail -Severity $severity -Result $result
    return $false
}
