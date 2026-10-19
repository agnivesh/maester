function Test-MtAnssiAdSchemaPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-028: Only privileged principals should control the schema objects.

    .DESCRIPTION
    Reads the owner and permissions of the schema container and of every class and attribute
    definition in it, and fails when a principal that is not privileged owns one or holds a right
    that gives control over it, such as writing its attributes, creating schema objects, or
    changing permissions or owner. Whoever can change a class definition can change the default
    permissions of every object later created from it, or the meaning of any attribute.
    Rights usable without a major prerequisite are level 1 (Critical), other potentially
    dangerous rights level 2 (High); the most severe level found is reported.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, when a read fails, when no schema object is visible (the account may lack read
    access), or when the permissions of an object cannot be read.

    .EXAMPLE
    Test-MtAnssiAdSchemaPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on
    a schema object, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdSchemaPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-028',
        Title = 'Only privileged principals should control the schema objects',
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

    Write-Verbose 'Starting Test-MtAnssiAdSchemaPermission'

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
    $schema = @($head -like 'CN=Schema,*')
    $objects = @(Get-MtAnssiAdObjectSecurity -DistinguishedName $schema `
            -ProtocolEvidence $adState.ProtocolEvidence) +
    @(Get-MtAnssiAdSearchSecurity -SearchBase $schema -Scope OneLevel `
            -Filter '(objectClass=*)' `
            -ProtocolEvidence $adState.ProtocolEvidence)

    $readable = @($objects | Where-Object { $null -ne $_.Ace }).Count
    if ($readable -ne [Math]::Max($objects.Count, 1)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No schema object is visible to the account that reads the directory, or the ' +
            'permissions of one could not be read.')
        return $null
    }

    $findings = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted)
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2) -Result (
            'No principal outside the privileged set holds a dangerous right on the ' +
            "$($objects.Count) schema objects.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    $result = "$($findings.Count) dangerous rights on schema objects are held by " +
        "principals outside the privileged set.$note`n`n$table"
    Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade @($findings.Level)) `
        -Result $result
    return $false
}
