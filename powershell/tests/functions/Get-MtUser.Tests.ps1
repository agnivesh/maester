Describe 'Get-MtUser' {
    BeforeAll {
        Import-Module $PSScriptRoot/../../Maester.psd1 -Force

        function New-MockMembers {
            param([int]$Count)
            1..$Count | ForEach-Object {
                @{ id = [guid]::NewGuid().ToString(); userPrincipalName = "user$_@contoso.com"; userType = 'Member' }
            }
        }

        # Wraps members in the raw Graph response shape that Invoke-MtGraphRequest returns when -DisablePaging is used.
        # Format-Result passes the raw wrapper through (RawOutput=$true), so production code must extract .value.
        function New-MockGroupMembersResponse {
            param([int]$Count)
            @{
                '@odata.context' = 'https://graph.microsoft.com/v1.0/$metadata#directoryObjects'
                'value'          = @(New-MockMembers -Count $Count)
            }
        }
    }

    Context 'When emergency access accounts are configured' {
        BeforeAll {
            $script:configuredUserId = '11111111-1111-1111-1111-111111111111'

            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { }
            Mock -ModuleName Maester Invoke-MtGraphRequest {
                if ($RelativeUri -like 'users/*') {
                    $id = $RelativeUri -replace '^users/', ''
                    return @{ id = $id; userPrincipalName = "$id@contoso.com"; userType = 'Member' }
                }
                if ($RelativeUri -like 'groups/*/members') { return New-MockGroupMembersResponse -Count 25 }
            }
        }

        It 'Should return the configured user and not read the Conditional Access policies' {
            Mock -ModuleName Maester Get-MtEmergencyAccessAccount {
                [pscustomobject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Y'; Type = 'user' }
            }
            $result = @(Get-MtUser -UserType EmergencyAccess)
            $result.Count | Should -Be 1
            $result[0].id | Should -Be $script:configuredUserId
            $result[0].userType | Should -Be 'EmergencyAccess'
            Should -Invoke Get-MtConditionalAccessPolicy -ModuleName Maester -Exactly 0
        }

        It 'Should treat the BreakGlass alias the same way' {
            Mock -ModuleName Maester Get-MtEmergencyAccessAccount {
                [pscustomobject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Y'; Type = 'user' }
            }
            @(Get-MtUser -UserType BreakGlass).id | Should -Be @($script:configuredUserId)
        }

        It 'Should return the members of a configured group' {
            Mock -ModuleName Maester Get-MtEmergencyAccessAccount {
                [pscustomobject]@{ ObjectId = '44444444-4444-4444-4444-444444444444'; DisplayName = 'G'; Type = 'group' }
            }
            $result = @(Get-MtUser -UserType EmergencyAccess -Count 30)
            $result.Count | Should -Be 25
            $result | ForEach-Object { $_.userType | Should -Be 'EmergencyAccess' }
            Should -Invoke Get-MtConditionalAccessPolicy -ModuleName Maester -Exactly 0
        }

        It 'Should return users and group members together and honour -Count' {
            Mock -ModuleName Maester Get-MtEmergencyAccessAccount {
                [pscustomobject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Y'; Type = 'user' }
                [pscustomobject]@{ ObjectId = '44444444-4444-4444-4444-444444444444'; DisplayName = 'G'; Type = 'group' }
            }
            @(Get-MtUser -UserType EmergencyAccess -Count 3).Count | Should -Be 3
            @(Get-MtUser -UserType EmergencyAccess -Count 100).Count | Should -Be 26
        }

        It 'Should throw when a configured account cannot be resolved' {
            Mock -ModuleName Maester Get-MtEmergencyAccessAccount {
                throw 'Could not resolve configured emergency access object(s): user: nobody@contoso.com (not found)'
            }
            { Get-MtUser -UserType EmergencyAccess } | Should -Throw '*Could not resolve configured emergency access*'
            Should -Invoke Get-MtConditionalAccessPolicy -ModuleName Maester -Exactly 0
        }

        It 'Should throw when a resolved account cannot be read' {
            Mock -ModuleName Maester Get-MtEmergencyAccessAccount {
                [pscustomobject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Y'; Type = 'user' }
            }
            Mock -ModuleName Maester Invoke-MtGraphRequest { throw 'Graph API error: Forbidden' }
            { Get-MtUser -UserType EmergencyAccess } | Should -Throw '*Forbidden*'
        }
    }

    Context 'When no emergency access accounts are configured' {
        BeforeAll {
            Mock -ModuleName Maester Get-MtEmergencyAccessAccount { return }
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { throw 'Detection must not read the Conditional Access policies.' }
            Mock -ModuleName Maester Invoke-MtGraphRequest { throw 'No Graph call is expected.' }
        }

        It 'Should return nothing for <UserType> and not guess from the Conditional Access policies' -ForEach @(
            @{ UserType = 'EmergencyAccess' }
            @{ UserType = 'BreakGlass' }
        ) {
            @(Get-MtUser -UserType $UserType -Count 5) | Should -BeNullOrEmpty
            Should -Invoke Get-MtConditionalAccessPolicy -ModuleName Maester -Exactly 0
            Should -Invoke Invoke-MtGraphRequest -ModuleName Maester -Exactly 0
        }
    }
}
