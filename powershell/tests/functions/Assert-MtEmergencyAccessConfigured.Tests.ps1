Describe 'Assert-MtEmergencyAccessConfigured' {
    BeforeAll {
        . "$PSScriptRoot/../helpers/Use-MtModuleFunction.ps1"
        Use-MtModuleFunction -Name Assert-MtEmergencyAccessConfigured
        Mock -ModuleName Maester Add-MtTestResultDetail { }
    }

    It 'Should skip the test and ask for the setting when nothing is configured' -ForEach @(
        @{ Setting = $null }
        @{ Setting = @() }
    ) {
        Mock -ModuleName Maester Get-MtSetting { $Setting }
        Assert-MtEmergencyAccessConfigured
        Should -Invoke Add-MtTestResultDetail -ModuleName Maester -Exactly 1 -ParameterFilter {
            $SkippedBecause -eq 'Custom' -and
            $SkippedCustomReason -like '*EmergencyAccessAccounts in maester-config.json*run Maester again*'
        }
    }

    It 'Should not skip when an account is configured' {
        Mock -ModuleName Maester Get-MtSetting { @(@{ Type = 'User'; UserPrincipalName = 'breakglass@contoso.com' }) }
        Assert-MtEmergencyAccessConfigured
        Should -Invoke Add-MtTestResultDetail -ModuleName Maester -Exactly 0
    }
}
