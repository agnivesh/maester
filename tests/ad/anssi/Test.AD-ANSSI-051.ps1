function Test-MtAnssiAdPrivilegedAdminCount {
    <#
    .SYNOPSIS
    ANSSI-AD-051: Privileged accounts should have adminCount set.

    .DESCRIPTION
    Fails when a privileged user account has adminCount unset or 0. Active Directory sets
    adminCount to 1 on every member, direct or nested, of a group it protects with AdminSDHolder,
    and on the built-in Administrator and krbtgt accounts. A cleared value on such an account was
    changed by someone, possibly to hide it from tools that look for adminCount.

    Accounts that are privileged only through their primary group are not checked: Microsoft does
    not document whether AdminSDHolder marks them.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when the members of a protected group cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_privileged_members_no_admincount.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedAdminCount

    Returns $true when every checked privileged user account has adminCount set, $false
    when one does not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedAdminCount
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-051',
        Title = 'Privileged accounts should have adminCount set',
        Product = 'ad',
        Feature = 'groups',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedAdminCount'

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

    $users = @($privileged.Account |
        Where-Object { $_.Kind -eq 'User' -and @($_.Link -ne 'PrimaryGroup').Count -gt 0 })
    $findings = @($users | Where-Object { [string]$_.Item.AdminCount -in '', '0' })
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Privileged users checked: $($users.Count), adminCount unset: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("All $($users.Count) privileged user accounts that are " +
            "members of a protected group have adminCount set.$note")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property { $_.Item.SamAccountName }) `
        -Column ([ordered]@{
            'Account'            = { $_.Item.SamAccountName }
            'adminCount'         = {
                if ($null -eq $_.Item.AdminCount) { 'not set' } else { $_.Item.AdminCount }
            }
            'Enabled'            = { $_.Item.Enabled }
            'Privileged through' = { $_.Group -join ', ' }
        })

    $result = "$($findings.Count) of $($users.Count) privileged user accounts that are members " +
        "of a protected group have adminCount unset or 0. Someone changed it on purpose.$note" +
        "`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
