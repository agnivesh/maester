BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-ComputerFixture {
        param(
            [string] $Name = 'SRV1',
            [string] $OperatingSystem = 'Windows Server 2022 Standard',
            [string[]] $ServicePrincipalName = @(),
            [int] $PrimaryGroupId = 515,
            [bool] $Enabled = $true
        )
        [PSCustomObject]@{
            DistinguishedName    = "CN=$Name,CN=Computers,DC=contoso,DC=com"
            Name                 = $Name
            OperatingSystem      = $OperatingSystem
            ServicePrincipalName = $ServicePrincipalName
            PrimaryGroupId       = $PrimaryGroupId
            Enabled              = $Enabled
        }
    }

    function Find-Server {
        param([object[]] $Computer, [object[]] $DomainController = @())
        InModuleScope Maester -Parameters @{ Computer = $Computer; Entry = $DomainController } {
            Get-MtAnssiAdServer -Computer $Computer -DomainController $Entry
        }
    }
}

Describe 'Get-MtAnssiAdServer' {
    It 'returns computers whose operating system contains Server' {
        $result = Find-Server -Computer @(
            Get-ComputerFixture -Name 'SRV1'
            Get-ComputerFixture -Name 'SRV2' -OperatingSystem 'Windows Server 2012 R2 Datacenter'
        )

        @($result.Server).Count | Should -Be 2
        @($result.Cluster).Count | Should -Be 0
    }

    It 'counts server editions whose name does not start with Windows Server' {
        $result = Find-Server -Computer @(
            Get-ComputerFixture -Name 'NAS1' -OperatingSystem 'Windows Storage Server 2016 Standard'
        )

        @($result.Server).Count | Should -Be 1
    }

    It 'leaves out workstations and computers without an operating system' {
        $result = Find-Server -Computer @(
            Get-ComputerFixture -Name 'PC1' -OperatingSystem 'Windows 11 Enterprise'
            Get-ComputerFixture -Name 'NOOS' -OperatingSystem ''
            Get-ComputerFixture -Name 'SRV1'
        )

        @($result.Server).Count | Should -Be 1
        $result.Server[0].Name | Should -Be 'SRV1'
    }

    It 'ignores the case of the operating system' {
        $result = Find-Server -Computer @(Get-ComputerFixture -OperatingSystem 'windows SERVER 19')

        @($result.Server).Count | Should -Be 1
    }

    It 'leaves out domain controllers found by primary group' {
        $result = Find-Server -Computer @(
            Get-ComputerFixture -Name 'DC1' -PrimaryGroupId 516
            Get-ComputerFixture -Name 'RO1' -PrimaryGroupId 521
            Get-ComputerFixture -Name 'SRV1'
        )

        @($result.Server).Count | Should -Be 1
        $result.Server[0].Name | Should -Be 'SRV1'
    }

    It 'leaves out domain controllers found by a controller entry' {
        $entry = [PSCustomObject]@{
            ServerReference = 'CN=ODD,CN=Computers,DC=contoso,DC=com'
        }
        $result = Find-Server -Computer @(Get-ComputerFixture -Name 'ODD'; Get-ComputerFixture) `
            -DomainController @($entry)

        @($result.Server).Count | Should -Be 1
        $result.Server[0].Name | Should -Be 'SRV1'
    }

    It 'returns cluster accounts apart from servers, with or without an operating system' {
        $spn = 'MSClusterVirtualServer/CLUSTER1'
        $result = Find-Server -Computer @(
            Get-ComputerFixture -Name 'CLUSTER1' -OperatingSystem '' -ServicePrincipalName $spn
            Get-ComputerFixture -Name 'NODE1' -ServicePrincipalName $spn
            Get-ComputerFixture -Name 'SRV1'
        )

        @($result.Cluster).Count | Should -Be 2
        @($result.Server).Count | Should -Be 1
        $result.Server[0].Name | Should -Be 'SRV1'
    }

    It 'recognises the cluster SPN among other SPNs and without regard to case' {
        $spns = @('HOST/vco1', 'msclustervirtualserver/vco1.contoso.com')
        $result = Find-Server -Computer @(
            Get-ComputerFixture -Name 'VCO1' -OperatingSystem '' -ServicePrincipalName $spns
        )

        @($result.Cluster).Count | Should -Be 1
    }

    It 'does not take another SPN that merely contains the cluster text' {
        $spn = 'HOST/MSClusterVirtualServer.example'
        $result = Find-Server -Computer @(Get-ComputerFixture -ServicePrincipalName $spn)

        @($result.Cluster).Count | Should -Be 0
        @($result.Server).Count | Should -Be 1
    }

    It 'returns disabled accounts too' {
        $result = Find-Server -Computer @(Get-ComputerFixture -Enabled $false)

        @($result.Server).Count | Should -Be 1
    }

    It 'copes with a missing SPN list' {
        $computer = Get-ComputerFixture
        $computer.ServicePrincipalName = $null

        @((Find-Server -Computer @($computer)).Server).Count | Should -Be 1
    }

    It 'returns empty lists without computers' {
        $result = InModuleScope Maester {
            Get-MtAnssiAdServer -Computer $null -DomainController $null
        }

        @($result.Server).Count | Should -Be 0
        @($result.Cluster).Count | Should -Be 0
    }
}
