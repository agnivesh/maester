BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Get-MtAnssiAdDomainController' {
    It 'finds writable and read-only controllers by primary group and ignores other computers' {
        $result = InModuleScope Maester {
            $computers = @(
                [PSCustomObject]@{ DistinguishedName = 'CN=DC1,OU=DC'; PrimaryGroupId = 516 }
                [PSCustomObject]@{ DistinguishedName = 'CN=RO1,OU=DC'; PrimaryGroupId = 521 }
                [PSCustomObject]@{ DistinguishedName = 'CN=PC1,CN=Computers'; PrimaryGroupId = 515 }
            )
            Get-MtAnssiAdDomainController -Computer $computers -DomainController @()
        }

        @($result).Count | Should -Be 2
        $result[0].Type | Should -Be 'Writable'
        $result[0].Computer.DistinguishedName | Should -Be 'CN=DC1,OU=DC'
        $result[1].Type | Should -Be 'ReadOnly'
    }

    It 'finds a controller through the server reference of a controller entry' {
        $result = InModuleScope Maester {
            $computers = @([PSCustomObject]@{ DistinguishedName = 'CN=odd,CN=Computers'
                    PrimaryGroupId = 515 })
            $entries = @([PSCustomObject]@{ Name = 'odd'; ServerReference = 'CN=odd,CN=Computers' })
            Get-MtAnssiAdDomainController -Computer $computers -DomainController $entries
        }

        @($result).Count | Should -Be 1
        $result[0].Type | Should -Be 'Writable'
        $result[0].DomainController.Name | Should -Be 'odd'
    }

    It 'matches the server reference without regard to case' {
        $result = InModuleScope Maester {
            $computers = @([PSCustomObject]@{ DistinguishedName = 'CN=DC1,OU=Domain Controllers'
                    PrimaryGroupId = 516 })
            $entries = @([PSCustomObject]@{ ServerReference = 'cn=dc1,ou=domain controllers' })
            Get-MtAnssiAdDomainController -Computer $computers -DomainController $entries
        }

        $result[0].DomainController | Should -Not -BeNullOrEmpty
    }

    It 'leaves the controller entry empty when none points to the computer' {
        $result = InModuleScope Maester {
            $computers = @([PSCustomObject]@{ DistinguishedName = 'CN=DC1'; PrimaryGroupId = 516 })
            Get-MtAnssiAdDomainController -Computer $computers -DomainController @()
        }

        $result[0].DomainController | Should -BeNullOrEmpty
    }

    It 'keeps the read-only type when a writable entry points to the computer' {
        $result = InModuleScope Maester {
            $computers = @([PSCustomObject]@{ DistinguishedName = 'CN=RO1'; PrimaryGroupId = 521 })
            $entries = @([PSCustomObject]@{ ServerReference = 'CN=RO1' })
            Get-MtAnssiAdDomainController -Computer $computers -DomainController $entries
        }

        $result[0].Type | Should -Be 'ReadOnly'
        $result[0].DomainController | Should -Not -BeNullOrEmpty
    }

    It 'ignores controller entries without a server reference' {
        $result = InModuleScope Maester {
            $computers = @([PSCustomObject]@{ DistinguishedName = ''; PrimaryGroupId = 515 })
            $entries = @([PSCustomObject]@{ ServerReference = '' })
            Get-MtAnssiAdDomainController -Computer $computers -DomainController $entries
        }

        @($result).Count | Should -Be 0
    }

    It 'returns an empty array for missing or empty input' {
        $result = InModuleScope Maester {
            , @(Get-MtAnssiAdDomainController -Computer $null -DomainController $null)
        }

        $result.Count | Should -Be 0
    }

    It 'accepts a primary group identifier stored as text' {
        $result = InModuleScope Maester {
            $computers = @([PSCustomObject]@{ DistinguishedName = 'CN=DC1'
                    PrimaryGroupId = '516' })
            Get-MtAnssiAdDomainController -Computer $computers -DomainController @()
        }

        @($result).Count | Should -Be 1
    }
}
