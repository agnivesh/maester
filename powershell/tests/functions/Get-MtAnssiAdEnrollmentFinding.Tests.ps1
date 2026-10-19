BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-RightFixture {
        param(
            [string] $Name, [string] $Sid = 'S-1-5-21-1-2-3-1105', [string] $Control = 'Enroll',
            [bool] $Inherited = $false
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=Certificate Templates"
            Name = $Name; Sid = $Sid; Control = $Control; IsInherited = $Inherited
        }
    }

    function Get-TemplateFixture {
        param([string] $Name, [bool] $Approval = $false)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=Certificate Templates"
            Name = $Name; ApprovalRequired = $Approval
        }
    }

    function Get-PublicationFixture {
        param([string[]] $Published = @(), [string[]] $Trusted = @())
        $ignoreCase = [System.StringComparer]::OrdinalIgnoreCase
        $set = [System.Collections.Generic.HashSet[string]]
        [PSCustomObject]@{
            Published = $set::new([string[]]$Published, $ignoreCase)
            Trusted   = $set::new([string[]]$Trusted, $ignoreCase)
        }
    }

    function Get-Finding {
        param([object[]] $Right, [object[]] $Template, [object] $Publication)
        $parameters = @{ Right = $Right; Template = $Template; Publication = $Publication }
        InModuleScope Maester -Parameters $parameters {
            param($Right, $Template, $Publication)
            @(Get-MtAnssiAdEnrollmentFinding -Right $Right -Template $Template `
                    -Publication $Publication)
        }
    }
}

Describe 'Get-MtAnssiAdEnrollmentFinding' {
    It 'gives level 1 and says whether a CA trusted for logon publishes the template' -ForEach @(
        @{ Published = @('ESC1'); Trusted = @('ESC1'); IsPublished = $true; IsTrusted = $true }
        @{ Published = @('ESC1'); Trusted = @(); IsPublished = $true; IsTrusted = $false }
        @{ Published = @(); Trusted = @(); IsPublished = $false; IsTrusted = $false }
    ) {
        $result = Get-Finding -Right @(Get-RightFixture -Name 'ESC1') `
            -Template @(Get-TemplateFixture -Name 'ESC1') `
            -Publication (Get-PublicationFixture -Published $Published -Trusted $Trusted)

        $result.Count | Should -Be 1
        $result[0].Level | Should -Be 1
        $result[0].Published | Should -Be $IsPublished
        $result[0].Trusted | Should -Be $IsTrusted
    }

    It 'matches the template name without regard to case' {
        $result = Get-Finding -Right @(Get-RightFixture -Name 'Esc1') `
            -Template @(Get-TemplateFixture -Name 'Esc1') `
            -Publication (Get-PublicationFixture -Published @('ESC1') -Trusted @('esc1'))

        $result[0].Trusted | Should -Be $true
    }

    It 'drops a right on a template that does not let the requester name the certificate' {
        $result = Get-Finding -Right @(
            Get-RightFixture -Name 'Safe'
            Get-RightFixture -Name 'ESC1'
        ) -Template @(Get-TemplateFixture -Name 'ESC1') `
            -Publication (Get-PublicationFixture -Published @('Safe', 'ESC1') -Trusted @('Safe'))

        @($result.Name) | Should -Be @('ESC1')
    }

    It 'joins a right to its template by distinguished name, not by name' {
        $other = Get-RightFixture -Name 'ESC1'
        $other.DistinguishedName = 'CN=ESC1,CN=Elsewhere'

        $result = Get-Finding -Right @($other) -Template @(Get-TemplateFixture -Name 'ESC1') `
            -Publication (Get-PublicationFixture -Published @('ESC1') -Trusted @('ESC1'))

        $result | Should -BeNullOrEmpty
    }

    It 'carries whether the template needs an approval' -ForEach @(
        @{ Approval = $true }
        @{ Approval = $false }
    ) {
        $result = Get-Finding -Right @(Get-RightFixture -Name 'ESC1') `
            -Template @(Get-TemplateFixture -Name 'ESC1' -Approval $Approval) `
            -Publication (Get-PublicationFixture)

        $result[0].ApprovalRequired | Should -Be $Approval
    }

    It 'keeps the identity of each right' {
        $result = Get-Finding -Right @(
            Get-RightFixture -Name 'ESC1' -Sid 'S-1-5-11' -Control 'GenericAll' -Inherited $true
        ) -Template @(Get-TemplateFixture -Name 'ESC1') -Publication (Get-PublicationFixture)

        $result[0].Sid | Should -BeExactly 'S-1-5-11'
        $result[0].Control | Should -BeExactly 'GenericAll'
        $result[0].IsInherited | Should -Be $true
        $result[0].Name | Should -BeExactly 'ESC1'
        $result[0].DistinguishedName | Should -BeExactly 'CN=ESC1,CN=Certificate Templates'
    }

    It 'returns one finding per right, in order' {
        $result = Get-Finding -Right @(
            Get-RightFixture -Name 'B' -Sid 'S-1-1-0'
            Get-RightFixture -Name 'A' -Sid 'S-1-5-11'
        ) -Template @(Get-TemplateFixture -Name 'A'; Get-TemplateFixture -Name 'B') `
            -Publication (Get-PublicationFixture -Published @('A') -Trusted @('A'))

        @($result | ForEach-Object { "$($_.Name):$($_.Level)" }) | Should -Be @('B:1', 'A:1')
    }

    It 'returns nothing when nobody can enroll' {
        Get-Finding -Right @() -Template @(Get-TemplateFixture -Name 'ESC1') `
            -Publication (Get-PublicationFixture) | Should -BeNullOrEmpty
    }

    It 'returns nothing when no template qualifies' {
        Get-Finding -Right @(Get-RightFixture -Name 'ESC1') -Template @() `
            -Publication (Get-PublicationFixture) | Should -BeNullOrEmpty
    }
}
