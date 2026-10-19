function Test-MtAnssiAdKdsRootKeyPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-026: Only privileged principals should control the KDS root keys.

    .DESCRIPTION
    Reads the owner and permissions of the Key Distribution Service (KDS) root keys of the forest
    and of the Master Root Keys container that holds them, and fails when a principal that is not
    privileged owns one or holds a right that gives control over it, such as full control, all
    extended rights, or changing its permissions or owner. The passwords of every group managed
    service account (gMSA) are derived from these keys. A forest without KDS root key has only the
    container to check, or nothing, and passes when it is clean.
    Rights usable without a major prerequisite are level 1 (Critical), other potentially
    dangerous rights level 2 (High); the most severe level found is reported.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, when a read fails, or when the permissions of an object cannot be read.

    .EXAMPLE
    Test-MtAnssiAdKdsRootKeyPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on
    a KDS root key, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdKdsRootKeyPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-026',
        Title = 'Only privileged principals should control the KDS root keys',
        Product = 'ad',
        Feature = 'permissions',
        Area = 'privileged-access',
        ResourceType = 'Permission',
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

    Write-Verbose 'Starting Test-MtAnssiAdKdsRootKeyPermission'

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
    $services = @($head -like 'CN=Configuration,*' | ForEach-Object { "CN=Services,$_" })
    $filter = '(|(&(objectClass=container)(cn=Master Root Keys))' +
    '(objectClass=msKds-ProvRootKey))'
    $objects = @(Get-MtAnssiAdSearchSecurity -SearchBase $services -Scope Subtree `
            -Filter $filter `
            -ProtocolEvidence $adState.ProtocolEvidence)

    if ($objects.Count -eq 0 -or @($objects | Where-Object { $null -eq $_.Ace }).Count -gt 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No KDS container is visible to the account that reads the directory, or the ' +
            'permissions of a KDS object could not be read. The account may lack read ' +
            'access, or the forest may predate the KDS (Windows Server 2012 schema).')
        return $null
    }

    $findings = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2) -Result (
            'No principal outside the privileged set holds a dangerous right on the ' +
            "$($objects.Count) KDS root key objects.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) dangerous rights on KDS root key objects are held by " +
        "principals outside the privileged set.$note`n`n$table"
    Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade @($findings.Level)) `
        -Result $result
    return $false
}
