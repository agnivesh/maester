Describe 'MT.1033 and MT.1034 instance sources' {
    BeforeAll {
        Import-Module $PSScriptRoot/../../Maester.psd1 -Force
        $testsRoot = Join-Path $PSScriptRoot '../../../tests/maester/entra'
        . (Join-Path $testsRoot 'Test.MT.1033.ps1')
        . (Join-Path $testsRoot 'Test.MT.1034.ps1')

        function New-FakeUser {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper creates an in-memory fixture and has no external side effects.')]
            param([string] $Name, [string] $UserType = 'Member')
            @{ id = "id-$Name"; userPrincipalName = "$Name@contoso.com"; userType = $UserType }
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
}
