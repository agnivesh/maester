function Test-MtAnssiAdPrivilegedContainerPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-049: Only privileged principals should control privileged account containers.

    .DESCRIPTION
    Reads the owner and permissions of every organizational unit and container above a privileged
    account, up to but not including the domain root, and fails when a principal that is not
    privileged owns one or holds a right that gives control over it, such as linking a group
    policy to it, changing its permissions or owner, or writing its attributes. Whoever can link
    a GPO to such a container can run code on the computers of the administrators or as them.
    Every finding counts as High.

    The test is skipped when the domain SID or name is not in the collected data, when a protected
    group is missing, when a read fails, when no container is visible (the account may lack read
    access), or when the permissions of a container cannot be read.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedContainerPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on a
    container of privileged accounts, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedContainerPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-049',
        Title = 'Only privileged principals should control privileged account containers',
        Product = 'ad',
        Feature = 'permissions',
        Area = 'privileged-access',
        ResourceType = 'Permission',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1098',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedContainerPermission'

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
    $container = @(Get-MtAnssiAdParentContainer -DomainDn $domainDn `
            -DistinguishedName @($privileged.Account.DistinguishedName))
    $objects = @(Get-MtAnssiAdObjectSecurity -ProtocolEvidence $adState.ProtocolEvidence `
            -DistinguishedName $container -Attribute @('gPLink', 'gPOptions'))

    $readable = @($objects | Where-Object { $null -ne $_.Ace }).Count
    if ($readable -ne [Math]::Max($objects.Count, 1)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No container of privileged accounts is visible to the account that reads the ' +
            'directory, or the permissions of one could not be read.')
        return $null
    }

    $findings = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted)
    $findings | ForEach-Object { $_.Level = 2; $_.Name = $_.DistinguishedName }
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Containers: $($objects.Count), dangerous rights: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ('No principal outside the privileged set holds a ' +
            "dangerous right on the $($objects.Count) containers of privileged accounts.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    Add-MtTestResultDetail -Result ("$($findings.Count) dangerous rights on containers of " +
        "privileged accounts are held by principals outside the privileged set.$note`n`n$table")
    return $false
}
