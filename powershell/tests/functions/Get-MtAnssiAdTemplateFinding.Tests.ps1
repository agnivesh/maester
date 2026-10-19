BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-RowFixture {
        param([string] $Name, [string] $Control = 'GenericAll', [int] $Level = 1)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=Certificate Templates"
            Name              = $Name
            Sid               = 'S-1-5-21-1-2-3-1105'
            Control           = $Control
            Level             = $Level
            IsInherited       = $true
        }
    }

    function Get-ServiceFixture {
        param([object] $Template)
        [PSCustomObject]@{ Name = 'CA'; Attribute = [ordered]@{ certificateTemplates = $Template } }
    }

    function Get-Finding {
        param([object[]] $Row, [object[]] $Service)
        InModuleScope Maester -Parameters @{ Row = $Row; Service = $Service } {
            param($Row, $Service)
            @(Get-MtAnssiAdTemplateFinding -Row $Row -EnrollmentService $Service)
        }
    }
}

Describe 'Get-MtAnssiAdTemplateFinding' {
    It 'gives level <Want> to a level <Level> right, template published: <Published>' -ForEach @(
        @{ Level = 1; Published = $true; Want = 1 }
        @{ Level = 2; Published = $true; Want = 2 }
        @{ Level = 1; Published = $false; Want = 2 }
        @{ Level = 2; Published = $false; Want = 2 }
    ) {
        $service = Get-ServiceFixture -Template @('Other')
        if ($Published) { $service = Get-ServiceFixture -Template @('Other', 'User') }

        $result = Get-Finding -Row @(Get-RowFixture -Name 'User' -Level $Level) -Service @($service)

        $result.Count | Should -Be 1
        $result[0].Level | Should -Be $Want
        $result[0].Published | Should -Be $Published
    }

    It 'keeps the other fields of the row' {
        $result = Get-Finding -Row @(Get-RowFixture -Name 'User' -Control 'WriteDacl') -Service @()

        $result[0].DistinguishedName | Should -BeExactly 'CN=User,CN=Certificate Templates'
        $result[0].Name | Should -BeExactly 'User'
        $result[0].Sid | Should -BeExactly 'S-1-5-21-1-2-3-1105'
        $result[0].Control | Should -BeExactly 'WriteDacl'
        $result[0].IsInherited | Should -Be $true
    }

    It 'leaves out AllExtendedRights, which grants enrollment' {
        $rows = @(
            Get-RowFixture -Name 'User' -Control 'AllExtendedRights'
            Get-RowFixture -Name 'User' -Control 'WriteOwner'
        )

        $result = Get-Finding -Row $rows -Service @()

        @($result.Control) -join ',' | Should -BeExactly 'WriteOwner'
    }

    It 'finds a template published by any service, in any case, with one or several names' {
        $services = @(
            Get-ServiceFixture -Template 'webserver'
            Get-ServiceFixture -Template $null
            Get-ServiceFixture -Template @('Machine', 'SubCA')
        )
        $rows = @(
            Get-RowFixture -Name 'WebServer'
            Get-RowFixture -Name 'SubCA'
            Get-RowFixture -Name 'Workstation'
        )

        $result = Get-Finding -Row $rows -Service $services

        @($result | ForEach-Object { "$($_.Name)=$($_.Level)" }) -join ',' |
            Should -BeExactly 'WebServer=1,SubCA=1,Workstation=2'
    }

    It 'returns nothing for no row' {
        (Get-Finding -Row @() -Service @(Get-ServiceFixture -Template 'User')).Count | Should -Be 0
    }
}
