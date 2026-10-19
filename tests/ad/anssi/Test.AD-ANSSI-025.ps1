function Test-MtAnssiAdDpapiBackupKeyPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-025: Only privileged principals should control the DPAPI backup keys.

    .DESCRIPTION
    Reads the owner and permissions of the DPAPI domain backup key objects (the BCKUPKEY secrets
    of the System container) and fails when a principal that is not privileged owns one or holds
    a right that gives control over it, such as full control, all extended rights, or changing its
    permissions or owner. These keys can decrypt the DPAPI data of every user of the domain: saved
    passwords, browser and mail secrets, certificates and Wi-Fi keys.
    Rights usable without a major prerequisite are level 1 (Critical), other potentially
    dangerous rights level 2 (High); the most severe level found is reported.

    The test is skipped when the domain SID or name is not in the collected data, when a
    protected group is missing, when a read fails, when no backup key object is found, or when the
    permissions of an object cannot be read.

    .EXAMPLE
    Test-MtAnssiAdDpapiBackupKeyPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on
    a DPAPI backup key, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDpapiBackupKeyPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-025',
        Title = 'Only privileged principals should control the DPAPI backup keys',
        Product = 'ad',
        Feature = 'permissions',
        Area = 'privileged-access',
        ResourceType = 'Permission',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1555',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDpapiBackupKeyPermission'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid -or -not $adState.Domain.DistinguishedName) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID or name was not found in the collected data.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $trusted = Get-MtAnssiAdTrustedSid -Privileged $privileged -Group $adState.Groups `
        -DomainSid $domainSid
    $system = "CN=System,$($adState.Domain.DistinguishedName)"
    $objects = @(Get-MtAnssiAdSearchSecurity -SearchBase @($system) -Scope OneLevel `
            -Filter '(&(objectClass=secret)(cn=BCKUPKEY*))' `
            -ProtocolEvidence $adState.ProtocolEvidence)

    $readable = @($objects | Where-Object { $null -ne $_.Ace }).Count
    if ($readable -ne [Math]::Max($objects.Count, 1)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No DPAPI backup key object was found, or the permissions of one could not be read.')
        return $null
    }

    $findings = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2) -Result (
            'No principal outside the privileged set holds a dangerous right on the ' +
            "$($objects.Count) DPAPI backup keys.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) dangerous rights on DPAPI backup keys are held by " +
        "principals outside the privileged set.$note`n`n$table"
    Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade @($findings.Level)) `
        -Result $result
    return $false
}
