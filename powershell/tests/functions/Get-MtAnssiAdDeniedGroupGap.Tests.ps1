BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:child = @(516, 521, 520, 512, 517, 502 | ForEach-Object { "S-1-5-21-1-2-3-$_" })
    $script:root = @($script:child) + @('S-1-5-21-1-2-3-518', 'S-1-5-21-1-2-3-519')

    function Get-Gap {
        param([AllowNull()] [string[]] $Sid, [switch] $Root)
        $parameters = @{ Sid = $Sid; DomainSid = $script:domainSid; Root = [bool]$Root }
        InModuleScope Maester -Parameters $parameters {
            param($Sid, $DomainSid, $Root)
            Get-MtAnssiAdDeniedGroupGap -MemberSid $Sid -DomainSid $DomainSid -IsForestRoot:$Root
        }
    }
}

Describe 'Get-MtAnssiAdDeniedGroupGap' {
    It 'returns nothing when a child domain group holds its default members' {
        @(Get-Gap -Sid $child).Count | Should -Be 0
    }

    It 'returns nothing when a root domain group holds its default members' {
        @(Get-Gap -Sid $root -Root).Count | Should -Be 0
    }

    It 'reports <Name> when it is missing' -ForEach @(
        @{ Name = 'Domain Controllers'; Rid = 516 }
        @{ Name = 'Read-only Domain Controllers'; Rid = 521 }
        @{ Name = 'Group Policy Creator Owners'; Rid = 520 }
        @{ Name = 'Domain Admins'; Rid = 512 }
        @{ Name = 'Cert Publishers'; Rid = 517 }
        @{ Name = 'krbtgt'; Rid = 502 }
        @{ Name = 'Schema Admins'; Rid = 518 }
        @{ Name = 'Enterprise Admins'; Rid = 519 }
    ) {
        $sids = @($root | Where-Object { $_ -ne "S-1-5-21-1-2-3-$Rid" })

        @(Get-Gap -Sid $sids -Root) | Should -Be @($Name)
    }

    It 'does not require Schema Admins and Enterprise Admins outside the root domain' {
        @(Get-Gap -Sid $child).Count | Should -Be 0
        @(Get-Gap -Sid $child -Root) -join ',' | Should -BeExactly 'Schema Admins,Enterprise Admins'
    }

    It 'reports every default member of an empty group, in order' {
        @(Get-Gap -Sid @() -Root) -join ',' | Should -BeExactly ('Domain Controllers,' +
            'Read-only Domain Controllers,Group Policy Creator Owners,Domain Admins,' +
            'Cert Publishers,krbtgt,Schema Admins,Enterprise Admins')
    }

    It 'treats a null member list as empty' {
        @(Get-Gap -Sid $null).Count | Should -Be 6
    }

    It 'requires the groups of this domain, not of another one' {
        $other = @(516, 521, 520, 512, 517, 502 | ForEach-Object { "S-1-5-21-9-9-9-$_" })

        @(Get-Gap -Sid $other).Count | Should -Be 6
    }
}
