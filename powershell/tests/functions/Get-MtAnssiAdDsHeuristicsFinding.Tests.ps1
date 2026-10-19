BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # The value ANSSI gives as the hardened one: every setting at its default, except
    # BlockOwnerImplicitRights and AttributeAuthorizationOnLDAPAdd which are explicitly 1.
    $script:clean = '0000000001000000000200000001130'

    function Get-DsHeuristicsValue {
        param([hashtable] $Override = @{})
        $characters = $script:clean.ToCharArray()
        foreach ($position in $Override.Keys) {
            $characters[$position - 1] = ([string]$Override[$position])[0]
        }
        -join $characters
    }

    function Get-Finding {
        param([AllowNull()] [AllowEmptyString()] [string] $Value)
        InModuleScope Maester -Parameters @{ Value = $Value } {
            Get-MtAnssiAdDsHeuristicsFinding -DsHeuristics $Value
        }
    }
}

Describe 'Get-MtAnssiAdDsHeuristicsFinding' {
    Context 'values without a finding' {
        It 'returns nothing for the hardened value' {
            @(Get-Finding -Value $script:clean).Count | Should -Be 0
        }

        It 'accepts the other values of the two hardening settings, as long as they count as 1' {
            $value = Get-DsHeuristicsValue -Override @{ 28 = 'x'; 29 = 'x' }

            @(Get-Finding -Value $value).Count | Should -Be 0
        }
    }

    Context 'an unset attribute' {
        It 'reports only the two settings that are not explicitly 1, as grade 4' {
            $findings = @(Get-Finding -Value $null)

            $findings.Setting | Should -Be 'AttributeAuthorizationOnLDAPAdd',
            'BlockOwnerImplicitRights'
            ($findings.Grade | Select-Object -Unique) | Should -Be 4
            ($findings.Value | Select-Object -Unique) | Should -Be 'not set'
            ($findings.Recommended | Select-Object -Unique) | Should -Be '1'
        }

        It 'gives the same result for an empty value' {
            @(Get-Finding -Value '').Count | Should -Be 2
        }
    }

    Context 'settings that break a rule' {
        It '<Setting> = <Character> is grade <Grade>' -ForEach @(
            @{ Setting = 'fAllowAnonNSPI'; Position = 8; Character = '1'; Grade = 1 }
            @{ Setting = 'dwAdminSDExMask'; Position = 16; Character = 'f'; Grade = 1 }
            @{ Setting = 'fLDAPBlockAnonOps'; Position = 7; Character = '2'; Grade = 2 }
            @{ Setting = 'DoNotVerifyUPNAndOrSPNUniqueness'; Position = 21
                Character = '3'; Grade = 2 }
            @{ Setting = 'AttributeAuthorizationOnLDAPAdd'; Position = 28
                Character = '2'; Grade = 2 }
            @{ Setting = 'BlockOwnerImplicitRights'; Position = 29; Character = '2'; Grade = 2 }
            @{ Setting = 'DisableConfidentialAttributeEncryptionRequirements'; Position = 31
                Character = '4'; Grade = 2 }
            @{ Setting = 'AttributeAuthorizationOnLDAPAdd'; Position = 28
                Character = '0'; Grade = 4 }
            @{ Setting = 'BlockOwnerImplicitRights'; Position = 29; Character = '3'; Grade = 4 }
        ) {
            $value = Get-DsHeuristicsValue -Override @{ $Position = $Character }
            $findings = @(Get-Finding -Value $value)

            $findings.Count | Should -Be 1
            $findings[0].Setting | Should -Be $Setting
            $findings[0].Grade | Should -Be $Grade
            $findings[0].Value | Should -Be $Character
            $findings[0].Position | Should -Be $Position
        }

        It 'does not report fLDAPBlockAnonOps for a value other than 2' {
            $value = Get-DsHeuristicsValue -Override @{ 7 = '1' }

            @(Get-Finding -Value $value).Count | Should -Be 0
        }

        It 'reports a setting once, with its most severe grade' {
            $value = Get-DsHeuristicsValue -Override @{ 28 = '2' }

            $all = @(Get-Finding -Value $value)
            $findings = @($all | Where-Object Setting -EQ 'AttributeAuthorizationOnLDAPAdd')

            $findings.Count | Should -Be 1
            $findings[0].Grade | Should -Be 2
        }

        It 'says what the recommended value is' {
            $value = Get-DsHeuristicsValue -Override @{ 7 = '2'; 8 = '1' }

            $byName = @{}
            foreach ($finding in Get-Finding -Value $value) {
                $byName[$finding.Setting] = $finding.Recommended
            }

            $byName['fLDAPBlockAnonOps'] | Should -Be 'not 2'
            $byName['fAllowAnonNSPI'] | Should -Be '0'
        }
    }

    Context 'ordering and short values' {
        It 'sorts the findings by grade, then by position' {
            $value = Get-DsHeuristicsValue -Override @{ 31 = '1'; 7 = '2'; 16 = '1' }

            $settings = @(Get-Finding -Value $value).Setting

            $settings | Should -Be 'dwAdminSDExMask', 'fLDAPBlockAnonOps',
            'DisableConfidentialAttributeEncryptionRequirements'
        }

        It 'treats the characters missing from a short value as 0' {
            $findings = @(Get-Finding -Value '0000002')

            $findings.Setting | Should -Be 'fLDAPBlockAnonOps', 'AttributeAuthorizationOnLDAPAdd',
            'BlockOwnerImplicitRights'
            $findings[0].Grade | Should -Be 2
        }

        It 'does not report fAllowAnonNSPI when the value stops before its position' {
            @(Get-Finding -Value '000000').Setting | Should -Not -Contain 'fAllowAnonNSPI'
        }
    }
}
