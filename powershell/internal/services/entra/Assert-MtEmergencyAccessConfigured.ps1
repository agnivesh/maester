function Assert-MtEmergencyAccessConfigured {
    <#
    .SYNOPSIS
        Skips the running test when no emergency access accounts are configured.

    .DESCRIPTION
        Checks the EmergencyAccessAccounts setting in maester-config.json. When it holds no entries, the
        running test is recorded as skipped with a message that asks for the setting and a rerun, and the
        skip ends the test. Maester does not guess which accounts are the emergency access accounts, because
        an account that is excluded from many Conditional Access policies is not necessarily one.

    .EXAMPLE
        Assert-MtEmergencyAccessConfigured

        Returns when at least one emergency access account or group is configured; skips the test otherwise.
    #>
    [CmdletBinding()]
    param ()

    if (Get-MtSetting -Name 'EmergencyAccessAccounts') {
        return
    }

    Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason 'No emergency access accounts are configured. Add them under EmergencyAccessAccounts in maester-config.json and run Maester again. See https://maester.dev/docs/configuration/emergency-access-accounts'
}
