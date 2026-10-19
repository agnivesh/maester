function Test-MtAnssiAdPrivilegedPasswordPolicy {
    <#
    .SYNOPSIS
    ANSSI-AD-050: Privileged accounts should have a strong password policy.

    .DESCRIPTION
    Finds the password policy that applies to each enabled privileged user account (its
    resultant fine-grained password policy, or else the domain password policy) and fails when it
    allows passwords shorter than 8 characters, or passwords that never expire or may stay
    unchanged for more than 3 years. A privileged account is a member, direct, nested or through
    its primary group, of a group that Active Directory protects with AdminSDHolder, or the
    built-in Administrator or krbtgt account.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when a read fails or a fine-grained password policy cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_privileged_members_password.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedPasswordPolicy

    Returns $true when every enabled privileged user account has a strong password policy,
    $false when one does not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedPasswordPolicy
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-050',
        Title = 'Privileged accounts should have a strong password policy',
        Product = 'ad',
        Feature = 'password-policy',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1110',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedPasswordPolicy'

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
    $policies = @(Get-MtAnssiAdEffectivePasswordPolicy -Account $users -Domain $adState.Domain `
            -ProtocolEvidence $adState.ProtocolEvidence)

    $findings = @($policies | Where-Object { $_.Weakness.Count -gt 0 })
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose "Enabled privileged users: $($users.Count), weak policy: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("All $($users.Count) enabled privileged user accounts " +
            "have a strong password policy.$note")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property { $_.Account.Item.SamAccountName }) `
        -DomainSource { $_.Account.DistinguishedName } `
        -Column ([ordered]@{
            'Account'            = { $_.Account.Item.SamAccountName }
            'Policy'             = { $_.Source }
            'Weakness'           = { $_.Weakness -join '; ' }
            'Privileged through' = { $_.Account.Group -join ', ' }
        })

    $result = "$($findings.Count) of $($users.Count) enabled privileged user accounts have a " +
        "weak password policy: passwords shorter than 8 characters, or that may stay unchanged " +
        "for more than 3 years.$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
