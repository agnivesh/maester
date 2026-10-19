function Test-MtAnssiAdPrivilegedGpoPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-030: Only privileged principals should control GPOs of privileged accounts.

    .DESCRIPTION
    Finds the group policy objects (GPOs) linked, directly or through inheritance, to the domain
    and organizational units that hold privileged accounts, and fails when a principal that is
    not privileged owns one or holds a right that gives control over it, such as changing its
    file path, writing its attributes, or changing its permissions or owner. Whoever controls
    such a GPO can run code as the administrators or on their computers. Disabled links, Block
    Inheritance and Enforced links are taken into account; security filtering, WMI filters and
    sites are not. Every finding counts as Critical.

    The test is skipped when the domain SID or name is not in the collected data, when a protected
    group is missing, when a read fails, when no GPO is visible (the account may lack read
    access), or when the permissions of a GPO cannot be read.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedGpoPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on a GPO
    applied to privileged accounts, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedGpoPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-030',
        Title = 'Only privileged principals should control GPOs of privileged accounts',
        Product = 'ad',
        Feature = 'group-policy',
        Area = 'privileged-access',
        ResourceType = 'GroupPolicy',
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

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedGpoPermission'

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
    $read = Get-MtAnssiAdPrivilegedGpo -Account @($privileged.Account.DistinguishedName) `
        -DomainDn $domainDn -ProtocolEvidence $adState.ProtocolEvidence

    $gpo = @($read.Gpo)
    $readable = @($gpo | Where-Object { $null -ne $_.Ace }).Count
    if ($readable -ne [Math]::Max($gpo.Count, 1)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No GPO applied to a privileged account is visible to the account that reads the ' +
            'directory, or the permissions of one could not be read.')
        return $null
    }

    $findings = @(Get-MtAnssiAdAceControl -Object $gpo -TrustedSid $trusted)
    $findings | ForEach-Object { $_.Level = 1 }
    $note = (Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved) + $read.Note

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ('No principal outside the privileged set holds a ' +
            "dangerous right on the $($gpo.Count) GPOs applied to privileged accounts.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    Add-MtTestResultDetail -Result ("$($findings.Count) dangerous rights on GPOs applied to " +
        "privileged accounts are held by principals outside the privileged set.$note`n`n$table")
    return $false
}
