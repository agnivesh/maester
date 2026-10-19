BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainSid = 'S-1-5-21-1-2-3'

    function Get-PrincipalFixture {
        param([string] $Name, [string] $Rid)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=x"
            Sid               = [PSCustomObject]@{ Value = "$script:domainSid-$Rid" }
        }
    }

    function Get-Trusted {
        param(
            [object] $Privileged, [object[]] $Group = @(), [AllowNull()] [string] $ForestRootSid
        )
        $parameters = @{
            Privileged = $Privileged; Group = $Group; DomainSid = $script:domainSid
            ForestRootSid = $ForestRootSid
        }
        InModuleScope Maester -Parameters $parameters {
            param($Privileged, $Group, $DomainSid, $ForestRootSid)
            $extra = @{}
            if ($ForestRootSid) { $extra.ForestRootSid = $ForestRootSid }
            $set = Get-MtAnssiAdTrustedSid -Privileged $Privileged -Group $Group `
                -DomainSid $DomainSid @extra
            [PSCustomObject]@{ Set = $set }
        }
    }
}

Describe 'Get-MtAnssiAdTrustedSid' {
    It 'returns one case-insensitive set with the fixed system and domain SIDs' {
        $result = Get-Trusted -Privileged ([PSCustomObject]@{ Account = @(); Group = @() })

        $result.Set -is [System.Collections.Generic.HashSet[string]] | Should -Be $true
        @($result.Set | Sort-Object) -join ',' | Should -BeExactly ((@(
                    'S-1-5-10', 'S-1-5-18', 'S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-516',
                    'S-1-5-21-1-2-3-521', 'S-1-5-21-1-2-3-526', 'S-1-5-32-544', 'S-1-5-9'
                ) | Sort-Object) -join ',')
        $result.Set.Contains('s-1-5-21-1-2-3-512') | Should -Be $true
    }

    It 'adds the privileged accounts and the walked groups found in the collected groups' {
        $privileged = [PSCustomObject]@{
            Account = @(
                [PSCustomObject]@{ Item = (Get-PrincipalFixture -Name 'alice' -Rid '1105') }
                [PSCustomObject]@{ Item = (Get-PrincipalFixture -Name 'PC1' -Rid '1106') }
            )
            Group   = @('CN=Tier0,DC=x', 'cn=helpdesk2,DC=x', 'CN=Gone,DC=x')
        }
        $groups = @(
            Get-PrincipalFixture -Name 'Tier0' -Rid '1200'
            Get-PrincipalFixture -Name 'Helpdesk' -Rid '1201'
            Get-PrincipalFixture -Name 'Helpdesk2' -Rid '1202'
        )

        $result = Get-Trusted -Privileged $privileged -Group $groups

        foreach ($rid in 1105, 1106, 1200, 1202) {
            $result.Set.Contains("S-1-5-21-1-2-3-$rid") | Should -Be $true
        }
        $result.Set.Contains('S-1-5-21-1-2-3-1201') | Should -Be $false
        $result.Set.Count | Should -Be 12
    }

    It 'accepts no collected groups' {
        $privileged = [PSCustomObject]@{ Account = @(); Group = @('CN=Tier0,DC=x') }

        (Get-Trusted -Privileged $privileged -Group $null).Set.Count | Should -Be 8
    }

    It 'also trusts the default groups of the forest root domain when it is another domain' {
        $privileged = [PSCustomObject]@{ Account = @(); Group = @() }

        $result = Get-Trusted -Privileged $privileged -ForestRootSid 'S-1-5-21-9-9-9'

        foreach ($rid in 512, 516, 521, 526) {
            $result.Set.Contains("S-1-5-21-9-9-9-$rid") | Should -Be $true
        }
        $result.Set.Contains('S-1-5-21-9-9-9-519') | Should -Be $false
        $result.Set.Contains('S-1-5-21-9-9-9-500') | Should -Be $false
        $result.Set.Count | Should -Be 12
    }

    It 'adds nothing when the forest root domain is the domain itself' {
        $privileged = [PSCustomObject]@{ Account = @(); Group = @() }

        $result = Get-Trusted -Privileged $privileged -ForestRootSid $script:domainSid

        $result.Set.Count | Should -Be 8
    }

    It 'keeps the SIDs of the domain when a forest root domain is given' {
        $privileged = [PSCustomObject]@{ Account = @(); Group = @() }

        $result = Get-Trusted -Privileged $privileged -ForestRootSid 'S-1-5-21-9-9-9'

        foreach ($rid in 512, 516, 521, 526) {
            $result.Set.Contains("S-1-5-21-1-2-3-$rid") | Should -Be $true
        }
    }
}
