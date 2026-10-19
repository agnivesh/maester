function Test-MtAnssiAdObjectOwner {
    <#
    .SYNOPSIS
    ANSSI-AD-058: Domain objects should have an expected owner.

    .DESCRIPTION
    Reads the owner of every user, computer, managed service account, group, organizational unit
    and GPO of the domain and fails when one created more than 7 days ago is owned by anyone
    other than Domain Admins, Enterprise Admins, Administrators or SYSTEM. The owner of an object
    can always change its permissions, so an unexpected owner keeps a way to take the object
    over.

    The test is skipped when the domain SID is not in the collected data, when the owners cannot
    be read, or when no object is found.

    Corresponds to the ANSSI Active Directory checkpoint vuln_owner.

    .EXAMPLE
    Test-MtAnssiAdObjectOwner

    Returns $true when every object older than 7 days has an expected owner, $false when one does
    not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdObjectOwner
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-058',
        Title = 'Domain objects should have an expected owner',
        Product = 'ad',
        Feature = 'permissions',
        Area = 'access-control',
        ResourceType = 'Permission',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdObjectOwner'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID was not found in the collected data.')
        return $null
    }

    $objects = @(Get-MtAnssiAdObjectOwner -ProtocolEvidence $adState.ProtocolEvidence)

    if ($objects.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No user, computer, group, organizational unit or GPO was found in the domain.')
        return $null
    }

    $findings = @(Get-MtAnssiAdOwnerFinding -Object $objects -DomainSid $domainSid `
            -Now (Get-Date).ToUniversalTime())
    $wrongCount = ($findings | Measure-Object -Property ObjectCount -Sum).Sum
    Write-Verbose "Objects: $($objects.Count), with an unexpected owner: $wrongCount"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("None of the $($objects.Count) users, computers, " +
            'groups, organizational units and GPOs read that are older than 7 days has an ' +
            'unexpected owner.')
        return $true
    }

    $index = Get-MtAnssiAdDirectoryIndex -User $adState.Users -Computer $adState.Computers `
        -Group $adState.Groups -DomainSid $domainSid
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $findings -Column ([ordered]@{
            'Owner'     = { [string]$index.BySid[$_.OwnerSid].Item.Name }
            'Owner SID' = { $_.OwnerSid }
            'Objects'   = { $_.ObjectCount }
            'Examples'  = { $_.Example -join ', ' }
        })

    $result = "$wrongCount object(s) older than 7 days are owned by $($findings.Count) owner(s) " +
        'other than Domain Admins, Enterprise Admins, Administrators or SYSTEM. An empty owner ' +
        'name means the owner is not in the collected data; an empty SID means the owner could ' +
        "not be read.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
