BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:now = [datetime]'2026-06-15T12:00:00'

    function Get-Object {
        param(
            [string] $Name,
            [AllowNull()] [string] $Owner = 'S-1-5-21-1-2-3-1105',
            [AllowNull()] [object] $Created = [datetime]'2025-01-01'
        )
        [PSCustomObject]@{ Name = $Name; OwnerSid = $Owner; Created = $Created }
    }

    function Get-Finding {
        param([object[]] $Object)
        $parameters = @{ Object = $Object; Now = $script:now }
        InModuleScope Maester -Parameters $parameters {
            param($Object, $Now)
            @(Get-MtAnssiAdOwnerFinding -Object $Object -DomainSid 'S-1-5-21-1-2-3' -Now $Now)
        }
    }
}

Describe 'Get-MtAnssiAdOwnerFinding' {
    It 'accepts the owner <Owner>' -ForEach @(
        @{ Owner = 'S-1-5-21-1-2-3-512' }
        @{ Owner = 'S-1-5-21-1-2-3-519' }
        @{ Owner = 'S-1-5-21-7-8-9-519' }
        @{ Owner = 'S-1-5-32-544' }
        @{ Owner = 'S-1-5-18' }
    ) {
        (Get-Finding -Object @(Get-Object -Name 'a' -Owner $Owner)).Count | Should -Be 0
    }

    It 'reports the owner <Owner>' -ForEach @(
        @{ Owner = 'S-1-5-21-9-9-9-512' }
        @{ Owner = 'S-1-5-21-1-2-3-1105' }
        @{ Owner = 'S-1-5-21-1-2-3-5190' }
        @{ Owner = 'S-1-5-32-548' }
    ) {
        $finding = Get-Finding -Object @(Get-Object -Name 'a' -Owner $Owner)

        $finding.Count | Should -Be 1
        $finding[0].OwnerSid | Should -BeExactly $Owner
    }

    It 'leaves out an object created in the last 7 days and checks one created <Case>' -ForEach @(
        @{ Case = 'exactly 7 days ago'; Days = 7 }
        @{ Case = 'at an unknown date'; Days = $null }
    ) {
        $created = $null
        if ($null -ne $Days) { $created = $script:now.AddDays(-$Days) }
        $finding = Get-Finding -Object @(
            Get-Object -Name 'recent' -Created $script:now.AddDays(-6.9)
            Get-Object -Name 'old' -Created $created
        )

        @($finding[0].Example) | Should -Be @('old')
    }

    It 'groups the objects by owner with a count and up to 3 examples, most objects first' {
        $finding = Get-Finding -Object @(
            Get-Object -Name 'u1' -Owner 'S-1-5-21-1-2-3-2000'
            Get-Object -Name 'h1'; Get-Object -Name 'h2'
            Get-Object -Name 'h3'; Get-Object -Name 'h4'
        )

        $finding.Count | Should -Be 2
        $finding[0].OwnerSid | Should -BeExactly 'S-1-5-21-1-2-3-1105'
        $finding[0].ObjectCount | Should -Be 4
        @($finding[0].Example) | Should -Be @('h1', 'h2', 'h3')
        $finding[1].ObjectCount | Should -Be 1
    }

    It 'sorts owners with the same count by SID' {
        $finding = Get-Finding -Object @(
            Get-Object -Name 'b' -Owner 'S-1-5-21-1-2-3-2002'
            Get-Object -Name 'a' -Owner 'S-1-5-21-1-2-3-2001'
        )

        @($finding.OwnerSid) | Should -Be @('S-1-5-21-1-2-3-2001', 'S-1-5-21-1-2-3-2002')
    }

    It 'reports objects whose owner could not be read under an empty SID' {
        $finding = Get-Finding -Object @(Get-Object -Name 'a' -Owner $null)

        $finding[0].OwnerSid | Should -BeExactly ''
    }

    It 'returns nothing for no object' {
        (Get-Finding -Object @()).Count | Should -Be 0
    }
}
