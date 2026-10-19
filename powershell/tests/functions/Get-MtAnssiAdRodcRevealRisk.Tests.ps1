BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:allowedDn = 'CN=Allowed RODC Password Replication Group,CN=Users,DC=contoso,DC=com'
    $script:adminsDn = 'CN=Domain Admins,CN=Users,DC=contoso,DC=com'
    $script:branchDn = 'CN=Branch Users,OU=Groups,DC=contoso,DC=com'
    $script:adminDn = 'CN=Administrator,CN=Users,DC=contoso,DC=com'
    $script:lookup = @{}
    $script:lookup[$script:allowedDn] = @{ Sid = 'S-1-5-21-1-2-3-571'; Name = 'Allowed RODC' }
    $script:lookup[$script:adminsDn] = @{ Sid = 'S-1-5-21-1-2-3-512'; Name = 'Domain Admins' }
    $script:lookup[$script:branchDn] = @{ Sid = 'S-1-5-21-1-2-3-1104'; Name = 'Branch Users' }
    $script:lookup[$script:adminDn] = @{ Sid = 'S-1-5-21-1-2-3-500'; Name = 'Administrator' }

    function Get-RodcFixture {
        param([string] $Name = 'RO1', [AllowNull()] [string[]] $Reveal = @($script:allowedDn))
        [PSCustomObject]@{
            Type     = 'ReadOnly'
            Computer = [PSCustomObject]@{
                Name                = $Name
                DistinguishedName   = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
                RevealOnDemandGroup = $Reveal
            }
        }
    }

    function Get-Risk {
        param([AllowNull()] [object[]] $Controller)
        $parameters = @{
            Controller = $Controller; Lookup = $script:lookup; Sid = $script:domainSid
        }
        InModuleScope Maester -Parameters $parameters {
            param($Controller, $Lookup, $Sid)
            Get-MtAnssiAdRodcRevealRisk -Controller $Controller -Lookup $Lookup -DomainSid $Sid
        }
    }
}

Describe 'Get-MtAnssiAdRodcRevealRisk' {
    It 'accepts the default Allowed RODC Password Replication Group' {
        $result = @(Get-Risk -Controller @(Get-RodcFixture))

        $result.Count | Should -Be 1
        @($result[0].Risky).Count | Should -Be 0
        $result[0].Unresolved | Should -Be 0
    }

    It 'accepts a custom group with a RID of 1000 or more' {
        $result = @(Get-Risk -Controller @(Get-RodcFixture -Reveal @($allowedDn, $branchDn)))

        @($result[0].Risky).Count | Should -Be 0
    }

    It 'reports a privileged group with its name and SID' {
        $result = @(Get-Risk -Controller @(Get-RodcFixture -Reveal @($allowedDn, $adminsDn)))

        @($result[0].Risky) | Should -Be @('Domain Admins (S-1-5-21-1-2-3-512)')
    }

    It 'reports a privileged user' {
        $result = @(Get-Risk -Controller @(Get-RodcFixture -Reveal @($adminDn)))

        @($result[0].Risky) | Should -Be @('Administrator (S-1-5-21-1-2-3-500)')
    }

    It 'reports a builtin or well-known principal listed as a foreign security principal' {
        $fsp = 'CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'

        $result = @(Get-Risk -Controller @(Get-RodcFixture -Reveal @($fsp)))

        @($result[0].Risky) | Should -Be @('S-1-1-0 (S-1-1-0)')
    }

    It 'reports RID 999 and accepts RID 1000' {
        $lookup['CN=R999,DC=contoso,DC=com'] = @{ Sid = 'S-1-5-21-1-2-3-999'; Name = 'R999' }
        $lookup['CN=R1000,DC=contoso,DC=com'] = @{ Sid = 'S-1-5-21-1-2-3-1000'; Name = 'R1000' }

        $result = @(Get-Risk -Controller @(Get-RodcFixture -Reveal @(
                    'CN=R999,DC=contoso,DC=com', 'CN=R1000,DC=contoso,DC=com')))

        @($result[0].Risky) | Should -Be @('R999 (S-1-5-21-1-2-3-999)')
    }

    It 'reports the allowed group of another domain' {
        $other = 'CN=Other Allowed,DC=other,DC=com'
        $lookup[$other] = @{ Sid = 'S-1-5-21-9-9-9-571'; Name = 'Other' }

        $result = @(Get-Risk -Controller @(Get-RodcFixture -Reveal @($other)))

        @($result[0].Risky).Count | Should -Be 1
    }

    It 'counts the entries outside the collected data without reporting them' {
        $result = @(Get-Risk -Controller @(Get-RodcFixture -Reveal @(
                    $allowedDn, 'CN=Somewhere,DC=other,DC=com', 'CN=Else,DC=other,DC=com')))

        @($result[0].Risky).Count | Should -Be 0
        $result[0].Unresolved | Should -Be 2
    }

    It 'returns one row per RODC with name and DN' {
        $result = @(Get-Risk -Controller @(
                (Get-RodcFixture -Name 'RO1')
                (Get-RodcFixture -Name 'RO2' -Reveal @($adminsDn))
            ))

        $result.Count | Should -Be 2
        $result[1].Name | Should -Be 'RO2'
        $result[1].DistinguishedName | Should -Be 'CN=RO2,OU=Domain Controllers,DC=contoso,DC=com'
        @($result[1].Risky).Count | Should -Be 1
    }

    It 'treats an empty or null list as harmless' {
        $result = @(Get-Risk -Controller @(
                (Get-RodcFixture -Name 'A' -Reveal @())
                (Get-RodcFixture -Name 'B' -Reveal $null)
            ))

        @($result | Where-Object { @($_.Risky).Count -gt 0 -or $_.Unresolved -gt 0 }).Count |
            Should -Be 0
    }
}
