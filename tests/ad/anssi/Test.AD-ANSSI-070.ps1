function Test-MtAnssiAdPrivilegedSecurityDescriptorReadable {
    <#
    .SYNOPSIS
    ANSSI-AD-070: The security descriptor of every privileged account should be readable.

    .DESCRIPTION
    Reads the security descriptor (owner, group and DACL) of every privileged account, users and
    computers, enabled or not, and fails when one cannot be read. The checks that depend on these
    descriptors are then incomplete for that account, and a descriptor hidden from ordinary
    readers can be a way to conceal a privileged account. A privileged account is a member,
    direct, nested or through its primary group, of a group that Active Directory protects with
    AdminSDHolder, or the built-in Administrator or krbtgt account.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when a read fails.

    Corresponds to the ANSSI Active Directory checkpoint vuln_sd_failed_sd_read_on_priv.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedSecurityDescriptorReadable

    Returns $true when every privileged account's security descriptor could be read, $false when
    one could not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedSecurityDescriptorReadable
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-070',
        Title = 'The security descriptor of every privileged account should be readable',
        Product = 'ad',
        Feature = 'permissions',
        Area = 'logging-and-detection',
        ResourceType = 'User',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedSecurityDescriptorReadable'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID was not found in the collected data.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $findings = @(Get-MtAnssiAdUnreadableDescriptor -Account $privileged.Account `
            -ProtocolEvidence $adState.ProtocolEvidence)

    $total = @($privileged.Account).Count
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Privileged accounts: $total, descriptor not readable: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("The security descriptor of all $total privileged " +
            "accounts could be read.$note")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property { $_.Item.SamAccountName }) `
        -Column ([ordered]@{
            'Account'            = { $_.Item.SamAccountName }
            'Type'               = { $_.Kind }
            'Privileged through' = { $_.Group -join ', ' }
        })

    $result = "The security descriptor of $($findings.Count) of $total privileged accounts " +
        "could not be read, so the checks that depend on it are incomplete for them.$note" +
        "`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
