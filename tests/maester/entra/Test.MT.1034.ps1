function Get-MtCaWhatIfEmergencyAccessInstance {
    <#
    .SYNOPSIS
    Returns one MT.1034 instance per emergency access account (up to five).

    .DESCRIPTION
    Instance source of the MT.1034 family. The suffix is the account's position in the list (MT.1034.0 to
    MT.1034.4) and the title names the account, as the Maester 2.x rows did.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $emergencyAccessUsers = @(Get-MtUser -Count 5 -UserType 'EmergencyAccess' | Where-Object { $_ })
    for ($i = 0; $i -lt $emergencyAccessUsers.Count; $i++) {
        $user = $emergencyAccessUsers[$i]
        [pscustomobject]@{
            Id    = [string]$i
            Title = "Emergency access users should not be blocked ($($user.userPrincipalName))"
            Data  = $user
        }
    }
}

function Test-MtCaWhatIfEmergencyAccessNotBlocked {
    <#
    .SYNOPSIS
    Checks with the Conditional Access What If API that no Conditional Access policy applies to an emergency access account.

    .DESCRIPTION
    Runs once per emergency access account returned by the instance source and evaluates an Exchange
    ActiveSync sign-in to Office 365 Exchange Online for that account. Passes when no policy applies.

    .LINK
    https://maester.dev/docs/tests/MT.1034
    #>
    [MaesterTest(
        Id = 'MT.1034',
        Title = 'Emergency access users should not be blocked.',
        Product = 'entra',
        Feature = 'conditional-access',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'None',
        Service = 'Graph',
        License = 'AAD_PREMIUM',
        LongRunning,
        InstanceSource = 'Get-MtCaWhatIfEmergencyAccessInstance',
        Author = 'merill',
        Contributor = ('f-bader', 'milanschwartz', 'jasperbaes')
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The emergency access account to evaluate, supplied by the engine.
        $Instance
    )

    $user = $Instance.Data.userPrincipalName
    $accountSource = if (Get-MtSetting -Name 'EmergencyAccessAccounts') {
        ''
    } else {
        "`n`n$user was treated as an emergency access account because it is one of the accounts excluded from the most Conditional Access policies. No EmergencyAccessAccounts are configured, so Maester inferred this. If $user is not an emergency access account, check why it is excluded from those policies, and list the real accounts under EmergencyAccessAccounts."
    }

    $policies = @(Test-MtConditionalAccessWhatIf -UserId $Instance.Data.id -IncludeApplications '00000002-0000-0ff1-ce00-000000000000' -ClientAppType exchangeActiveSync | Where-Object { $_ })
    if ($policies.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. No Conditional Access policy applies to $user, so it can still sign in when other access is lost.$accountSource"
        return $true
    }
    # The blocking policies belong under the remediation action, before the related links.
    $template = Get-MtTestResultTemplate -TestId 'MT.1034' -CommandName 'Test-MtCaWhatIfEmergencyAccessNotBlocked'
    $policyList = Get-GraphObjectMarkdown -GraphObjects $policies -GraphObjectType ConditionalAccess
    $policyBlock = "Conditional Access policies that apply to ${user}:`n`n$policyList"
    $sections = $template.Description -split '(?=### Related links)', 2
    $description = ($sections[0].TrimEnd(), $policyBlock, $sections[1]).Where({ $_ }) -join "`n`n"
    $policyCount = $policies.Count
    Add-MtTestResultDetail -Description $description -Result "Found $policyCount Conditional Access $(if ($policyCount -eq 1) { 'policy that applies' } else { 'policies that apply' }) to $user. An emergency access account must be excluded from every policy that could block it, or it cannot be used when other access is lost.$accountSource"
    return $false
}
