Describe 'Get-MtUser' {
    BeforeAll {
        Import-Module $PSScriptRoot/../../Maester.psd1 -Force

        # GUIDs used as test fixtures. Also available as literals in ParameterFilter blocks.
        $script:smallGroupId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"   # small/valid EA group
        $script:largeGroupId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"   # large/wrong group
        $script:dummyGroupId = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"   # second group for detection

        # The detection algorithm requires exactly 2 candidate groups (PossibleEmergencyAccessGroups.Count -eq 2).
        # Each helper creates policies ensuring at least 2 distinct groups appear in excludeGroups.
        #
        # Non-tied case: primary group excluded from all 3 policies, dummy only from 2.
        #   → primary count=3, dummy count=2 → primary is selected alone.
        #
        # Tied case: both groups excluded from all 3 policies.
        #   → both count=3 → both are selected (triggering the size-guard logic).

        function New-MockCaPolicy {
            param([string[]]$ExcludeGroups = @(), [string[]]$ExcludeUsers = @())
            [PSCustomObject]@{
                id         = [guid]::NewGuid().ToString()
                state      = 'enabled'
                conditions = [PSCustomObject]@{
                    applications = [PSCustomObject]@{
                        includeApplications                          = @('All')
                        includeAuthenticationContextClassReferences  = $null
                    }
                    users = [PSCustomObject]@{
                        includeUsers  = @('All')
                        excludeUsers  = $ExcludeUsers
                        excludeGroups = $ExcludeGroups
                    }
                }
            }
        }

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

    Context 'When CA policies have no group exclusions' {
        BeforeAll {
            $policies = @((New-MockCaPolicy), (New-MockCaPolicy))
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest { return $null }
        }

        It 'Should return an empty result without calling the members endpoint' {
            $result = Get-MtUser -UserType EmergencyAccess
            $result | Should -BeNullOrEmpty
            Should -Invoke Invoke-MtGraphRequest -ModuleName Maester -Exactly 0 -ParameterFilter {
                $RelativeUri -like 'groups/*/members'
            }
        }
    }

    Context 'When the auto-detected group is small (valid emergency access group)' {
        BeforeAll {
            # Primary (small) in all 3 policies, dummy only in 2 — primary wins detection
            $policies = @(
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId)
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest {
                if ($RelativeUri -like 'groups/*/members') { return New-MockGroupMembersResponse -Count 2 }
            }
        }

        It 'Should return members and mark them as EmergencyAccess' {
            $result = Get-MtUser -UserType EmergencyAccess
            $result | Should -Not -BeNullOrEmpty
            $result | ForEach-Object { $_.userType | Should -Be 'EmergencyAccess' }
        }

        It 'Should call the members endpoint for the correct group' {
            $null = Get-MtUser -UserType EmergencyAccess
            # Use inline literal GUID to avoid ParameterFilter closure-scope issues
            Should -Invoke Invoke-MtGraphRequest -ModuleName Maester -ParameterFilter {
                $RelativeUri -eq 'groups/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/members'
            }
        }
    }

    Context 'When the auto-detected group has more than 20 members (large / wrong group)' {
        BeforeAll {
            # Large group in all 3 policies, dummy only in 2 — large group is detected
            $policies = @(
                New-MockCaPolicy -ExcludeGroups @($script:largeGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:largeGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:largeGroupId)
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest {
                if ($RelativeUri -like 'groups/*/members') { return New-MockGroupMembersResponse -Count 25 }
            }
        }

        It 'Should return an empty result when the detected group is too large' {
            $result = Get-MtUser -UserType EmergencyAccess
            $result | Should -BeNullOrEmpty
        }

        It 'Should issue a warning when skipping a large group' {
            $null = Get-MtUser -UserType EmergencyAccess -WarningVariable warnings
            $warnings | Should -Not -BeNullOrEmpty
            # Warning must reference the rejected group GUID (inline literal to avoid scope issue)
            $warnings[0] | Should -Match 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        }
    }

    Context 'When two groups are tied in CA policy exclusion count (one large, one small)' {
        BeforeAll {
            # Both excluded from all 3 policies — tied, so both are selected
            $policies = @(
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:largeGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:largeGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:largeGroupId)
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest {
                if ($RelativeUri -eq 'groups/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/members') {
                    return New-MockGroupMembersResponse -Count 2
                }
                if ($RelativeUri -eq 'groups/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/members') {
                    return New-MockGroupMembersResponse -Count 50
                }
            }
        }

        It 'Should return members only from the small group' {
            # -Count 5 ensures we retrieve all small group members without early exit
            $result = Get-MtUser -UserType EmergencyAccess -Count 5
            $result | Should -Not -BeNullOrEmpty
            # Large group has 50 members which is rejected; only 2 from the small group should be here
            $result.Count | Should -Be 2
        }

        It 'Should call the large group members endpoint (but reject the results)' {
            $null = Get-MtUser -UserType EmergencyAccess -Count 5
            Should -Invoke Invoke-MtGraphRequest -ModuleName Maester -ParameterFilter {
                $RelativeUri -eq 'groups/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/members'
            }
        }
    }

    Context 'When group members endpoint is called with -DisablePaging' {
        BeforeAll {
            $policies = @(
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId)
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest { return New-MockGroupMembersResponse -Count 2 }
        }

        It 'Should pass -DisablePaging to Invoke-MtGraphRequest to prevent infinite paging loops' {
            $null = Get-MtUser -UserType EmergencyAccess
            Should -Invoke Invoke-MtGraphRequest -ModuleName Maester -ParameterFilter {
                $RelativeUri -like 'groups/*/members' -and $DisablePaging -eq $true
            }
        }
    }

    Context 'When -Count parameter is specified' {
        BeforeAll {
            $policies = @(
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId)
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest {
                if ($RelativeUri -like 'groups/*/members') { return New-MockGroupMembersResponse -Count 5 }
            }
        }

        It 'Should return no more users than the -Count limit' {
            $result = Get-MtUser -UserType EmergencyAccess -Count 3
            $result | Should -Not -BeNullOrEmpty
            $result.Count | Should -BeLessOrEqual 3
        }
    }

    Context 'When an error occurs fetching group members' {
        BeforeAll {
            $policies = @(
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId)
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest {
                if ($RelativeUri -like 'groups/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/members') {
                    throw "Graph API error: group not found"
                }
            }
        }

        It 'Should issue a warning that contains the group GUID (not a user GUID)' {
            $null = Get-MtUser -UserType EmergencyAccess -WarningVariable warnings
            $warnings | Should -Not -BeNullOrEmpty
            $warnings[0] | Should -Match 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        }

        It 'Should not throw when the Graph call fails' {
            { Get-MtUser -UserType EmergencyAccess } | Should -Not -Throw
        }
    }

    Context 'When a null or empty group GUID reaches the fetch loop' {
        BeforeAll {
            # Simulate the edge case where Group-Object produces an empty-string bucket
            $policies = @(
                New-MockCaPolicy -ExcludeGroups @('', $script:smallGroupId)
                New-MockCaPolicy -ExcludeGroups @('', $script:smallGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId)
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest { return New-MockGroupMembersResponse -Count 2 }
        }

        It 'Should never call groups//members with an empty GUID segment' {
            $null = Get-MtUser -UserType EmergencyAccess
            Should -Invoke Invoke-MtGraphRequest -ModuleName Maester -Exactly 0 -ParameterFilter {
                $RelativeUri -like 'groups//members'
            }
        }
    }

    Context 'When using BreakGlass alias for UserType' {
        BeforeAll {
            $policies = @(
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId, $script:dummyGroupId)
                New-MockCaPolicy -ExcludeGroups @($script:smallGroupId)
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest {
                if ($RelativeUri -like 'groups/*/members') { return New-MockGroupMembersResponse -Count 2 }
            }
        }

        It 'Should return results and set userType to EmergencyAccess (function hardcodes this value)' {
            $result = Get-MtUser -UserType BreakGlass
            $result | Should -Not -BeNullOrEmpty
            # The function always sets userType = "EmergencyAccess" regardless of -UserType parameter value
            $result | ForEach-Object { $_.userType | Should -Be 'EmergencyAccess' }
        }
    }

    Context 'When emergency access accounts are configured' {
        BeforeAll {
            $script:configuredUserId = '11111111-1111-1111-1111-111111111111'  # Y: the configured account
            $script:detectedUserId = '22222222-2222-2222-2222-222222222222'    # X: what detection would pick
            $script:otherUserId = '33333333-3333-3333-3333-333333333333'

            # Detection would pick X and the other user: both are excluded from the most policies.
            $policies = @(
                New-MockCaPolicy -ExcludeUsers @($script:detectedUserId, $script:otherUserId)
                New-MockCaPolicy -ExcludeUsers @($script:detectedUserId, $script:otherUserId)
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
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

        It 'Should return the configured account and not the account that detection would pick' {
            Mock -ModuleName Maester Get-MtEmergencyAccessAccount {
                [pscustomobject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Y'; Type = 'user' }
            }
            $result = @(Get-MtUser -UserType EmergencyAccess -Count 5)
            $result.id | Should -Be @($script:configuredUserId)
            $result.id | Should -Not -Contain $script:detectedUserId
            $result.id | Should -Not -Contain $script:otherUserId
        }

        It 'Should treat the BreakGlass alias the same way' {
            Mock -ModuleName Maester Get-MtEmergencyAccessAccount {
                [pscustomobject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Y'; Type = 'user' }
            }
            @(Get-MtUser -UserType BreakGlass).id | Should -Be @($script:configuredUserId)
        }

        It 'Should return the members of a configured group, beyond the 20 members detection accepts' {
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

        It 'Should throw when a configured account cannot be resolved and not fall back to detection' {
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
            $policies = @(
                New-MockCaPolicy -ExcludeUsers @('22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333')
                New-MockCaPolicy -ExcludeUsers @('22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333')
            )
            Mock -ModuleName Maester Get-MtConditionalAccessPolicy { return $policies }
            Mock -ModuleName Maester Invoke-MtGraphRequest {
                $id = $RelativeUri -replace '^users/', ''
                return @{ id = $id; userPrincipalName = "$id@contoso.com"; userType = 'Member' }
            }
        }

        It 'Should detect the accounts from the Conditional Access policies' {
            $result = @(Get-MtUser -UserType EmergencyAccess -Count 5)
            $result.id | Should -Be @('22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333')
            Should -Invoke Get-MtConditionalAccessPolicy -ModuleName Maester -Exactly 1
        }
    }
}
