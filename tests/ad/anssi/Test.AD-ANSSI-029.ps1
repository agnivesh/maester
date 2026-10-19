function Test-MtAnssiAdMicrosoftDnsPermission {
    <#
    .SYNOPSIS
    ANSSI-AD-029: Only privileged principals should control the MicrosoftDNS containers.

    .DESCRIPTION
    Reads the owner and permissions of the MicrosoftDNS containers (below CN=System of the domain
    and in the DomainDnsZones and ForestDnsZones partitions) and fails when a principal that is
    not privileged owns one or holds a right that gives control over it, such as full control,
    changing its permissions or owner, writing its attributes or creating objects in it. Writing
    the settings of the DNS service can make it run code, usually on the domain controllers.
    DnsAdmins has such rights by default and is not trusted.

    The test is skipped when the domain SID or name is not in the collected data, when a
    protected group is missing, when a read fails, when no container is visible (the account may
    lack read access, or the domain may not host DNS in Active Directory), or when the
    permissions of a container cannot be read.

    .EXAMPLE
    Test-MtAnssiAdMicrosoftDnsPermission

    Returns $true when no principal outside the privileged set holds a dangerous right on a
    MicrosoftDNS container, $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdMicrosoftDnsPermission
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-029',
        Title = 'Only privileged principals should control the MicrosoftDNS containers',
        Product = 'ad',
        Feature = 'permissions',
        Area = 'access-control',
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

    Write-Verbose 'Starting Test-MtAnssiAdMicrosoftDnsPermission'

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
    $head = @(Get-MtAnssiAdNamingContextHead -ProtocolEvidence $adState.ProtocolEvidence)
    $parent = @("CN=System,$domainDn") + @($head -match '^DC=(Domain|Forest)DnsZones,')
    $objects = @(Get-MtAnssiAdSearchSecurity -SearchBase $parent -Scope OneLevel `
            -Filter '(&(objectClass=container)(cn=MicrosoftDNS))' `
            -ProtocolEvidence $adState.ProtocolEvidence)

    $readable = @($objects | Where-Object { $null -ne $_.Ace }).Count
    if ($readable -ne [Math]::Max($objects.Count, 1)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No MicrosoftDNS container is visible to the account that reads the directory, or ' +
            'the permissions of one could not be read. The account may lack read access, or ' +
            'the domain may not host DNS in Active Directory.')
        return $null
    }

    $findings = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $trusted)
    $findings | ForEach-Object { $_.Level = 1; $_.Name = $_.DistinguishedName }
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "MicrosoftDNS containers: $($objects.Count), dangerous rights: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ('No principal outside the privileged set holds a ' +
            "dangerous right on the $($objects.Count) MicrosoftDNS containers.$note")
        return $true
    }

    $principal = @($adState.Users) + @($adState.Computers) + @($adState.Groups)
    $table = Format-MtAnssiAdAceControlTable -Row $findings -Principal $principal
    Add-MtTestResultDetail -Result ("$($findings.Count) dangerous rights on MicrosoftDNS " +
        "containers are held by principals outside the privileged set.$note`n`n$table")
    return $false
}
