function Test-MtAnssiAdSidHistoryDangerous {
    <#
    .SYNOPSIS
    ANSSI-AD-053: No SID history should hold a well-known or privileged SID.

    .DESCRIPTION
    Fails when the sIDHistory attribute of a user, computer or group holds a SID that a domain
    migration never produces:

    - A well-known SID, any SID outside the domain SIDs S-1-5-21-a-b-c-rid, for example Everyone,
      SYSTEM or the built-in Administrators group.
    - A privileged domain SID, a domain SID with a relative identifier below 1000: Administrator,
      krbtgt, Domain Admins, Enterprise Admins and the other accounts and groups that Windows
      creates itself.

    Ordinary account and group SIDs (relative identifier of 1000 or more) are not reported here.
    Disabled accounts are included.

    The test is skipped when no user, computer or group is in the collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_sidhistory_dangerous.

    .EXAMPLE
    Test-MtAnssiAdSidHistoryDangerous

    Returns $true when no SID history holds a well-known or privileged SID, $false when one does,
    and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdSidHistoryDangerous
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-053',
        Title = 'No SID history should hold a well-known or privileged SID',
        Product = 'ad',
        Feature = 'users',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'High',
        Mitre = 'T1134.005',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdSidHistoryDangerous'

    $riskLabel = @{
        WellKnown        = 'Well-known SID'
        PrivilegedDomain = 'Privileged domain SID'
    }

    $adState = Get-MtADDomainState -Categories @('Users', 'Computers', 'Groups')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState -Name 'Users', 'Computers', 'Groups'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    $total = @($adState.Users).Count + @($adState.Computers).Count + @($adState.Groups).Count
    if ($total -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No user, computer or group was found in the collected data.')
        return $null
    }

    $objects = @(Get-MtAnssiAdSidHistoryObject -User $adState.Users -Computer $adState.Computers `
            -Group $adState.Groups)
    $dangerous = @(Get-MtAnssiAdDangerousSidHistory -Object $objects)
    Write-Verbose "With SID history: $($objects.Count), dangerous SIDs: $($dangerous.Count)"

    if ($dangerous.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "None of the $($objects.Count) users, computers and groups with a SID history has " +
            'a well-known or privileged SID in it.')
        return $true
    }

    $affected = @($dangerous | Select-Object -Property Type, Name -Unique).Count
    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($dangerous | Sort-Object -Property Risk, Type, Name) `
        -Column ([ordered]@{
            'Type'       = { $_.Type }
            'Name'       = { $_.Name }
            'SID'        = { $_.Sid }
            'Risk'       = { $riskLabel[$_.Risk] }
            'Last logon' = { Format-MtAnssiAdDate $_.LastLogonDate -NullText 'n/a' }
        })

    $result = "$affected users, computers and groups have an unexpected SID in their SID " +
        'history, a well-known SID or a privileged domain SID. An attacker can use it to grant ' +
        "themselves illegitimate access rights.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
