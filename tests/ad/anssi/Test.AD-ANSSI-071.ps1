function Test-MtAnssiAdSidHistoryPresent {
    <#
    .SYNOPSIS
    ANSSI-AD-071: Users, computers and groups should not have a SID history.

    .DESCRIPTION
    Fails when the sIDHistory attribute of a user, computer or group has a value. The attribute
    keeps the access of an account or group migrated from another domain. It should be cleared as
    soon as the migrations are completed. Disabled accounts are included.

    The test is skipped when no user, computer or group is in the collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_sidhistory_present.

    .EXAMPLE
    Test-MtAnssiAdSidHistoryPresent

    Returns $true when no object has a SID history, $false when one has, and $null when the test
    is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdSidHistoryPresent
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-071',
        Title = 'Users, computers and groups should not have a SID history',
        Product = 'ad',
        Feature = 'users',
        Area = 'identity-lifecycle',
        ResourceType = 'User',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1134.005',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdSidHistoryPresent'

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

    if ($objects.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "None of the $total users, computers and groups has a SID history.")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($objects | Sort-Object -Property Type, Name) `
        -Column ([ordered]@{
            'Type'        = { $_.Type }
            'Name'        = { $_.Name }
            'SID history' = { $_.SidHistory }
            'Last logon'  = { Format-MtAnssiAdDate $_.LastLogonDate -NullText 'n/a' }
        })

    $result = "$($objects.Count) of $total users, computers and groups have a SID history. The " +
        'attribute is only needed during domain migrations. Left in place, it keeps access ' +
        "to resources of the former domain and can be abused to gain access rights.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
