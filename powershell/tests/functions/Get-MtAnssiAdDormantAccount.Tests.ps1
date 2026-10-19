BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Get-MtAnssiAdDormantAccount' {
    BeforeAll {
        $script:now = (Get-Date).ToUniversalTime()
    }

    It 'counts the enabled accounts and returns the dormant ones with their type' {
        $result = InModuleScope Maester -Parameters @{ Now = $script:now } {
            $dormant = [PSCustomObject]@{
                SamAccountName = 'old'; Enabled = $true; Created = $Now.AddDays(-3000)
                PasswordLastSet = $Now.AddDays(-1500); LastLogonDate = $Now.AddDays(-500)
            }
            $active = [PSCustomObject]@{
                SamAccountName = 'active'; Enabled = $true; Created = $Now.AddDays(-3000)
                PasswordLastSet = $Now.AddDays(-10); LastLogonDate = $Now.AddDays(-1)
            }
            Get-MtAnssiAdDormantAccount -Account @($dormant, $active) -Type User `
                -PasswordCutoff $Now.AddYears(-3) -ActivityCutoff $Now.AddYears(-1)
        }

        $result.EnabledCount | Should -Be 2
        @($result.Dormant).Count | Should -Be 1
        $result.Dormant[0].SamAccountName | Should -Be 'old'
        $result.Dormant[0].Type | Should -Be 'User'
    }

    It 'skips disabled accounts in the count and in the result' {
        $result = InModuleScope Maester -Parameters @{ Now = $script:now } {
            $disabled = [PSCustomObject]@{
                SamAccountName = 'off'; Enabled = $false; Created = $Now.AddDays(-3000)
                PasswordLastSet = $Now.AddDays(-1500); LastLogonDate = $Now.AddDays(-500)
            }
            Get-MtAnssiAdDormantAccount -Account @($disabled) -Type Computer `
                -PasswordCutoff $Now.AddYears(-3) -ActivityCutoff $Now.AddYears(-1)
        }

        $result.EnabledCount | Should -Be 0
        @($result.Dormant).Count | Should -Be 0
    }

    It 'uses the creation date for an account that never logged on' {
        $result = InModuleScope Maester -Parameters @{ Now = $script:now } {
            $oldGhost = [PSCustomObject]@{
                SamAccountName = 'oldghost'; Enabled = $true; Created = $Now.AddDays(-400)
                PasswordLastSet = $Now.AddDays(-1500); LastLogonDate = $null
            }
            $newGhost = [PSCustomObject]@{
                SamAccountName = 'newghost'; Enabled = $true; Created = $Now.AddDays(-100)
                PasswordLastSet = $Now.AddDays(-1500); LastLogonDate = $null
            }
            Get-MtAnssiAdDormantAccount -Account @($oldGhost, $newGhost) -Type User `
                -PasswordCutoff $Now.AddYears(-3) -ActivityCutoff $Now.AddYears(-1)
        }

        @($result.Dormant).Count | Should -Be 1
        $result.Dormant[0].SamAccountName | Should -Be 'oldghost'
    }

    It 'treats a password that was never set as old' {
        $result = InModuleScope Maester -Parameters @{ Now = $script:now } {
            $noPassword = [PSCustomObject]@{
                SamAccountName = 'nopwd'; Enabled = $true; Created = $Now.AddDays(-3000)
                PasswordLastSet = $null; LastLogonDate = $Now.AddDays(-500)
            }
            Get-MtAnssiAdDormantAccount -Account @($noPassword) -Type User `
                -PasswordCutoff $Now.AddYears(-3) -ActivityCutoff $Now.AddYears(-1)
        }

        @($result.Dormant).Count | Should -Be 1
    }

    It 'accepts null and empty input' {
        $results = InModuleScope Maester -Parameters @{ Now = $script:now } {
            $cutoffs = @{ PasswordCutoff = $Now.AddYears(-3); ActivityCutoff = $Now.AddYears(-1) }
            @(
                Get-MtAnssiAdDormantAccount -Account $null -Type User @cutoffs
                Get-MtAnssiAdDormantAccount -Account @() -Type User @cutoffs
            )
        }

        $results | ForEach-Object { $_.EnabledCount | Should -Be 0 }
        $results | ForEach-Object { @($_.Dormant).Count | Should -Be 0 }
    }
}
