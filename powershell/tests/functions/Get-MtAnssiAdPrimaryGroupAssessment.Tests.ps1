BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:writableDc = 532480
    $script:readOnlyDc = 83890176
    $script:workstation = 4096

    function Get-UserFixture {
        param([string] $Name = 'alice', [object] $Group = 513, [object] $Enabled = $true)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,OU=Users,DC=contoso,DC=com"
            Name              = $Name
            Enabled           = $Enabled
            PrimaryGroupId    = $Group
        }
    }

    function Get-ComputerFixture {
        param([string] $Name = 'PC1$', [object] $Group = 515, [object] $Uac = 4096)
        [PSCustomObject]@{
            DistinguishedName  = "CN=$Name,CN=Computers,DC=contoso,DC=com"
            Name               = $Name
            Enabled            = $true
            PrimaryGroupId     = $Group
            UserAccountControl = $Uac
        }
    }

    function Get-Assessment {
        param([AllowNull()] [object[]] $User, [AllowNull()] [object[]] $Computer)
        InModuleScope Maester -Parameters @{ User = $User; Computer = $Computer } {
            param($User, $Computer)
            Get-MtAnssiAdPrimaryGroupAssessment -User $User -Computer $Computer
        }
    }
}

Describe 'Get-MtAnssiAdPrimaryGroupAssessment' {
    Context 'user accounts' {
        It 'accepts Domain Users and Domain Guests' {
            $result = @(Get-Assessment -User @(
                    (Get-UserFixture -Name 'a' -Group 513)
                    (Get-UserFixture -Name 'g' -Group 514)
                ))

            $result.Count | Should -Be 2
            @($result | Where-Object { $_.IsDeviation }).Count | Should -Be 0
            $result[0].Type | Should -Be 'User'
            $result[0].Expected | Should -Be '513 or 514'
        }

        It 'flags a privileged primary group' {
            $result = @(Get-Assessment -User @(Get-UserFixture -Group 512))

            $result[0].IsDeviation | Should -Be $true
            $result[0].PrimaryGroupId | Should -Be 512
        }

        It 'flags the group of computers and a custom group' {
            $result = @(Get-Assessment -User @(
                    (Get-UserFixture -Name 'c' -Group 515)
                    (Get-UserFixture -Name 'x' -Group 1105)
                ))

            @($result | Where-Object { $_.IsDeviation }).Count | Should -Be 2
        }

        It 'reads a primary group id given as text' {
            $result = @(Get-Assessment -User @(Get-UserFixture -Group '513'))

            $result[0].PrimaryGroupId | Should -Be 513
            $result[0].IsDeviation | Should -Be $false
        }

        It 'keeps disabled accounts and reports their state' {
            $result = @(Get-Assessment -User @(Get-UserFixture -Group 512 -Enabled $false))

            $result.Count | Should -Be 1
            $result[0].Enabled | Should -Be $false
            $result[0].IsDeviation | Should -Be $true
        }
    }

    Context 'computer accounts' {
        It 'accepts Domain Computers for a workstation or server' {
            $computer = Get-ComputerFixture -Group 515 -Uac $workstation
            $result = @(Get-Assessment -Computer @($computer))

            $result[0].Type | Should -Be 'Computer'
            $result[0].Expected | Should -Be '515'
            $result[0].IsDeviation | Should -Be $false
        }

        It 'flags a server whose primary group is Domain Controllers' {
            $computer = Get-ComputerFixture -Group 516 -Uac $workstation
            $result = @(Get-Assessment -Computer @($computer))

            $result[0].IsDeviation | Should -Be $true
        }

        It 'accepts Domain Controllers for a writable domain controller' {
            $result = @(Get-Assessment -Computer @(Get-ComputerFixture -Group 516 -Uac $writableDc))

            $result[0].Type | Should -Be 'DomainController'
            $result[0].Expected | Should -Be '516'
            $result[0].IsDeviation | Should -Be $false
        }

        It 'flags a writable domain controller with another primary group' {
            $result = @(Get-Assessment -Computer @(Get-ComputerFixture -Group 512 -Uac $writableDc))

            $result[0].IsDeviation | Should -Be $true
        }

        It 'flags a writable domain controller with Domain Computers' {
            $result = @(Get-Assessment -Computer @(Get-ComputerFixture -Group 515 -Uac $writableDc))

            $result[0].IsDeviation | Should -Be $true
        }

        It 'accepts the read-only group for a read-only domain controller' {
            $result = @(Get-Assessment -Computer @(Get-ComputerFixture -Group 521 -Uac $readOnlyDc))

            $result[0].Type | Should -Be 'ReadOnlyDomainController'
            $result[0].Expected | Should -Be '521'
            $result[0].IsDeviation | Should -Be $false
        }

        It 'flags a read-only domain controller with the writable group' {
            $result = @(Get-Assessment -Computer @(Get-ComputerFixture -Group 516 -Uac $readOnlyDc))

            $result[0].IsDeviation | Should -Be $true
        }

        It 'treats a computer without userAccountControl as a plain computer' {
            $result = @(Get-Assessment -Computer @(Get-ComputerFixture -Group 515 -Uac $null))

            $result[0].Type | Should -Be 'Computer'
            $result[0].IsDeviation | Should -Be $false
        }
    }

    Context 'data' {
        It 'returns nothing for null or empty input' {
            @(Get-Assessment -User $null -Computer $null).Count | Should -Be 0
            @(Get-Assessment -User @() -Computer @()).Count | Should -Be 0
        }

        It 'does not return accounts without a primary group id' {
            $result = @(Get-Assessment -User @(
                    (Get-UserFixture -Name 'none' -Group $null)
                    (Get-UserFixture -Name 'junk' -Group 'x')
                    (Get-UserFixture -Name 'ok' -Group 513)
                ))

            $result.Count | Should -Be 1
            $result[0].Name | Should -Be 'ok'
        }

        It 'returns users and computers together with their names and DNs' {
            $result = @(Get-Assessment -User @(Get-UserFixture -Name 'u1') `
                    -Computer @(Get-ComputerFixture -Name 'c1$'))

            $result.Count | Should -Be 2
            ($result | Where-Object { $_.Name -eq 'u1' }).DistinguishedName |
                Should -Be 'CN=u1,OU=Users,DC=contoso,DC=com'
            ($result | Where-Object { $_.Name -eq 'c1$' }).Type | Should -Be 'Computer'
        }
    }
}
