function Test-MtAnssiAdAdminSdHolderPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-022: AdminSDHolder should grant dangerous rights only to privileged principals.

    .DESCRIPTION
    Reads the owner and permissions of the AdminSDHolder object and fails when a principal that is
    not privileged owns it or holds a right that gives control over it, such as full control,
    the right to change its permissions or owner, or the right to write its attributes. Active
    Directory copies the permissions of AdminSDHolder to every protected account and group every
    hour, so such a right reaches all administrators. The rights are judged as if they were on
    those users, computers and groups. Privileged principals are the members,
    direct, nested or through their primary group, of the groups Active Directory protects with
    AdminSDHolder, those groups themselves, and a few system principals.

    Rights that need no major prerequisite are level 1 (Critical); other potentially dangerous
    rights are level 2 (High). The test reports the most severe level it found.

    The test is skipped when the domain SID or name is not in the collected data, when a protected
    group is missing, when a read fails, or when the permissions of AdminSDHolder cannot be read.

    .EXAMPLE
    Test-MtAnssiAdAdminSdHolderPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on
    AdminSDHolder, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdAdminSdHolderPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-022',
        Title = 'AdminSDHolder should grant dangerous rights only to privileged principals',
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

    Write-Verbose 'Starting Test-MtAnssiAdAdminSdHolderPermission'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

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
    $target = @(Get-MtAnssiAdObjectSecurity -ProtocolEvidence $adState.ProtocolEvidence `
            -DistinguishedName "CN=AdminSDHolder,CN=System,$domainDn")

    if ($null -eq $target[0].Ace) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The permissions of the AdminSDHolder object could not be read.')
        return $null
    }

    $template = $target[0].PSObject.Copy()
    $template.ObjectClass = @('user', 'computer', 'group')
    $findings = @(Get-MtAnssiAdAceControl -Object @($template) -TrustedSid $trusted)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Dangerous rights on AdminSDHolder: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2) -Result (
            'No principal outside the privileged set holds a dangerous right on ' +
            "AdminSDHolder.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) dangerous rights on AdminSDHolder are held by principals " +
        "outside the privileged set. AdminSDHolder passes its permissions on to every " +
        "protected account and group.$note`n`n$table"

    $severity = Get-MtAnssiAdSeverity -Grade @($findings.Level)
    Add-MtTestResultDetail -Severity $severity -Result $result
    return $false
}
