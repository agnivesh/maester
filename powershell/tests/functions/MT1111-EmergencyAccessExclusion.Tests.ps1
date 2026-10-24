Describe 'MT.1111 emergency access exclusion' {
    BeforeAll {
        Import-Module $PSScriptRoot/../../Maester.psd1 -Force
        . (Join-Path $PSScriptRoot '../../../tests/maester/xspm/Test.MT.1111.ps1')

        # Internal helpers the check calls while it writes the result.
        function Get-MtXspmPrivilegedClassificationIcon { '' }
        function Get-MtSafeMarkdown { param($Text) $Text }
        function Get-MtXspmUnifiedIdentityInfo { }

        function New-UnlinkedAdmin {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper creates an in-memory fixture and has no external side effects.')]
            param([string] $Name)
            [pscustomobject]@{
                Type                     = 'User'
                AccountStatus            = 'Enabled'
                AccountUpn               = "$Name@contoso.com"
                AccountDisplayName       = $Name
                Classification           = 'ControlPlane'
                AssociatedPrimaryAccount = $null
                AssignedEntraRoles       = @([pscustomobject]@{ Classification = 'ControlPlane'; RoleIsPrivileged = $true; RoleDefinitionName = 'Global Administrator' })
                CriticalAssetDetails     = ''
                AccountObjectId          = "id-$Name"
            }
        }

        Mock Get-MtXspmUnifiedIdentityInfo { @((New-UnlinkedAdmin -Name 'breakglass'), (New-UnlinkedAdmin -Name 'regular')) }
        Mock Add-MtTestResultDetail { }
    }

    It 'Should leave out an account that is configured by object id' {
        # The setting holds an Id, not a UserPrincipalName; Get-MtUser resolves it.
        Mock Get-MtUser { @(@{ id = 'id-breakglass'; userPrincipalName = 'breakglass@contoso.com'; userType = 'EmergencyAccess' }) }

        Test-MtXspmPrivilegedUsersLinkedToIdentity | Should -BeFalse
        Should -Invoke Add-MtTestResultDetail -Exactly 1 -ParameterFilter {
            $Result -like '*regular*' -and $Result -notlike '*breakglass*'
        }
    }

    It 'Should leave out the members of a configured group' {
        Mock Get-MtUser {
            @(
                @{ id = 'id-breakglass'; userPrincipalName = 'breakglass@contoso.com'; userType = 'EmergencyAccess' }
                @{ id = 'id-regular'; userPrincipalName = 'regular@contoso.com'; userType = 'EmergencyAccess' }
            )
        }

        Test-MtXspmPrivilegedUsersLinkedToIdentity | Should -BeTrue
    }

    It 'Should report every unlinked account when none are configured' {
        Mock Get-MtUser { }

        Test-MtXspmPrivilegedUsersLinkedToIdentity | Should -BeFalse
        Should -Invoke Add-MtTestResultDetail -Exactly 1 -ParameterFilter {
            $Result -like '*regular*' -and $Result -like '*breakglass*'
        }
    }
}
