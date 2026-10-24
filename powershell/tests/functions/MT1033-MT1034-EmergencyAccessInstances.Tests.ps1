Describe 'MT.1033 and MT.1034 instance sources' {
    BeforeAll {
        Import-Module $PSScriptRoot/../../Maester.psd1 -Force
        $testsRoot = Join-Path $PSScriptRoot '../../../tests/maester/entra'
        . (Join-Path $testsRoot 'Test.MT.1033.ps1')
        . (Join-Path $testsRoot 'Test.MT.1034.ps1')

        function Get-BreakGlassInstance {
            [pscustomobject]@{ Data = @{ id = '11111111-2222-3333-4444-555555555555'; userPrincipalName = 'breakglass@contoso.com' } }
        }

        # Stands in for the internal helper; the tests below make it skip.
        function Assert-MtEmergencyAccessConfigured { }

        function New-FakeUser {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper creates an in-memory fixture and has no external side effects.')]
            param([string] $Name, [string] $UserType = 'Member')
            @{ id = "id-$Name"; userPrincipalName = "$Name@contoso.com"; userType = $UserType }
        }
    }

    Context 'When no emergency access accounts are configured' {
        BeforeAll {
            Mock Assert-MtEmergencyAccessConfigured { throw 'test skipped' }
            Mock Get-MtUser { }
        }

        It 'MT.1033 and MT.1034 skip before reading any user' {
            { Get-MtCaWhatIfRegularUserInstance } | Should -Throw 'test skipped'
            { Get-MtCaWhatIfEmergencyAccessInstance } | Should -Throw 'test skipped'
            Should -Invoke Get-MtUser -Exactly 0
        }
    }

    Context 'When six emergency access accounts are configured and the member sample holds the last one' {
        BeforeAll {
            # Get-MtUser stands in for the configured accounts: it honours -Count like the real function.
            Mock Get-MtUser {
                if ($UserType -eq 'EmergencyAccess') {
                    $all = 1..6 | ForEach-Object { New-FakeUser -Name "ea$_" -UserType 'EmergencyAccess' }
                    return @($all | Select-Object -First $Count)
                }
                # The first five members that Graph returns: ea2..ea6 are emergency access accounts.
                return @(2..6 | ForEach-Object { New-FakeUser -Name "ea$_" })
            }
        }

        It 'MT.1033 leaves every configured account out of the users it checks' {
            @(Get-MtCaWhatIfRegularUserInstance) | Should -BeNullOrEmpty
        }
    }

    Context 'When the member sample holds one regular user and one emergency access account' {
        BeforeAll {
            Mock Get-MtUser {
                if ($UserType -eq 'EmergencyAccess') { return @(New-FakeUser -Name 'breakglass' -UserType 'EmergencyAccess') }
                return @((New-FakeUser -Name 'breakglass'), (New-FakeUser -Name 'alice'))
            }
        }

        It 'MT.1033 checks only the regular user' {
            $instances = @(Get-MtCaWhatIfRegularUserInstance)
            $instances.Count | Should -Be 1
            $instances[0].Data.userPrincipalName | Should -Be 'alice@contoso.com'
        }

        It 'MT.1034 lists only the emergency access account' {
            $instances = @(Get-MtCaWhatIfEmergencyAccessInstance)
            $instances.Count | Should -Be 1
            $instances[0].Data.userPrincipalName | Should -Be 'breakglass@contoso.com'
            $instances[0].Title | Should -BeLike '*breakglass@contoso.com*'
        }
    }

    Context 'MT.1034 result text' {
        BeforeAll {
            function Get-MtTestResultTemplate { }
            function Get-GraphObjectMarkdown { }
            Mock Get-MtTestResultTemplate { [pscustomobject]@{ Description = "Overview.`n`n#### Remediation action`n`nExclude the account.`n`n### Related links`n`n* A link" } }
            Mock Get-GraphObjectMarkdown { '  - [Block legacy](https://example.test/policy)' }
            Mock Add-MtTestResultDetail { }
        }

        It 'Should pass without extra text when the account is configured and no policy applies' {
            Mock Get-MtSetting { @(@{ Type = 'User'; UserPrincipalName = 'breakglass@contoso.com' }) }
            Mock Test-MtConditionalAccessWhatIf { @() }
            Test-MtCaWhatIfEmergencyAccessNotBlocked -Instance (Get-BreakGlassInstance) | Should -BeTrue
            Should -Invoke Add-MtTestResultDetail -Exactly 1 -ParameterFilter { $Result -like 'Well done*' -and $Result -notlike '*inferred*' }
        }

        It 'Should list the blocking policies under the remediation action, not in the result' {
            Mock Get-MtSetting { @(@{ Type = 'User'; UserPrincipalName = 'breakglass@contoso.com' }) }
            Mock Test-MtConditionalAccessWhatIf { @([pscustomobject]@{ displayName = 'Block legacy' }) }
            Test-MtCaWhatIfEmergencyAccessNotBlocked -Instance (Get-BreakGlassInstance) | Should -BeFalse
            Should -Invoke Add-MtTestResultDetail -Exactly 1 -ParameterFilter {
                $Description -like '*#### Remediation action*policies that apply to breakglass@contoso.com:*Block legacy*### Related links*' -and
                $Result -like 'Found 1 Conditional Access policy that applies to breakglass@contoso.com.*cannot be used when other access is lost*' -and
                $Result -notlike '*Block legacy*'
            }
        }
    }
}
