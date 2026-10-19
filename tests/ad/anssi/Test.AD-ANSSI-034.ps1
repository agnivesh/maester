function Test-MtAnssiAdPrivilegedServicePrincipalName {
    <#
    .SYNOPSIS
    ANSSI-AD-034: Privileged user accounts should not have a service principal name.

    .DESCRIPTION
    Fails when an enabled privileged user account has a servicePrincipalName. Any domain user can
    then request a service ticket encrypted with a key derived from its password and try to crack
    it offline. A privileged account is a member, direct, nested or through its primary group, of
    a group that Active Directory protects with AdminSDHolder, or the built-in Administrator or
    krbtgt account. Managed service accounts are computer objects and are not checked.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when the members of a protected group cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_spn_priv.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedServicePrincipalName

    Returns $true when no enabled privileged user account has a service principal name, $false
    when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedServicePrincipalName
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-034',
        Title = 'Privileged user accounts should not have a service principal name',
        Product = 'ad',
        Feature = 'service-principal-names',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1558.003',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedServicePrincipalName'

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
        Where-Object { $_.Kind -eq 'User' -and $_.Item.Enabled -eq $true })
    $findings = @($users |
        Where-Object { @($_.Item.ServicePrincipalName | Where-Object { $_ }).Count -gt 0 })
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Enabled privileged users: $($users.Count), with an SPN: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("None of the $($users.Count) enabled privileged user " +
            "accounts has a service principal name.$note")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property { $_.Item.PasswordLastSet }) `
        -Column ([ordered]@{
            'Account'                 = { $_.Item.SamAccountName }
            'Service principal names' = { @($_.Item.ServicePrincipalName) -join ', ' }
            'Privileged through'      = { $_.Group -join ', ' }
            'Password last set'       = { Format-MtAnssiAdDate $_.Item.PasswordLastSet }
        })

    $result = "$($findings.Count) of $($users.Count) enabled privileged user accounts have a " +
        'service principal name. Any domain user can request a ticket for them and try to crack ' +
        "their password offline.$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
