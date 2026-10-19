BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Use-Ldap {
        param([hashtable] $GpLink)
        $script:gpLinkByDn = $GpLink
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith {
            foreach ($dn in $DistinguishedName) {
                if ($Attribute -contains 'displayName') {
                    [PSCustomObject]@{
                        DistinguishedName = $dn; Name = ($dn -split ',')[0] -replace '^cn=', ''
                        Ace = @()
                        Attribute = [ordered]@{ displayName = "GPO $(($dn -split ',')[0])" }
                    }
                } else {
                    [PSCustomObject]@{
                        DistinguishedName = $dn; Name = 'c'; Ace = @()
                        Attribute = [ordered]@{
                            gPLink = $script:gpLinkByDn[$dn]; gPOptions = $null
                        }
                    }
                }
            }
        }
    }

    function Get-PrivilegedGpo {
        param([string[]] $Account)
        $evidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        InModuleScope Maester -Parameters @{ Account = $Account; Evidence = $evidence } {
            param($Account, $Evidence)
            Get-MtAnssiAdPrivilegedGpo -Account $Account -DomainDn 'DC=x' `
                -ProtocolEvidence $Evidence
        }
    }
}

Describe 'Get-MtAnssiAdPrivilegedGpo' {
    It 'reads the containers and the GPOs of the domain that apply, named by display name' {
        Use-Ldap -GpLink @{
            'DC=x'       = '[LDAP://cn={D},cn=policies,cn=system,DC=x;0]' +
            '[LDAP://cn={F},cn=policies,cn=system,DC=other;0]'
            'OU=t0,DC=x' = '[LDAP://cn={A},cn=policies,cn=system,DC=x;0]'
        }

        $result = Get-PrivilegedGpo -Account @('CN=alice,OU=t0,DC=x')

        @($result.Gpo.Name | Sort-Object) -join ';' |
            Should -BeExactly 'GPO cn={A} ({A});GPO cn={D} ({D})'
        $result.Note | Should -BeExactly ' 1 GPOs of another domain were not checked.'
        Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            ($DistinguishedName -join ';') -eq 'OU=t0,DC=x;DC=x' -and
            ($Attribute -join ',') -eq 'gPLink,gPOptions' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
        }
        Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            @($DistinguishedName).Count -eq 2 -and ($Attribute -join ',') -eq 'displayName' -and
            $ProtocolEvidence.ResolvedServer -eq 'dc1'
        }
    }

    It 'gives an empty note when every GPO is in the domain' {
        Use-Ldap -GpLink @{ 'DC=x' = '[LDAP://cn={D},cn=policies,cn=system,dc=X;0]' }

        $result = Get-PrivilegedGpo -Account @('CN=alice,DC=x')

        $result.Note | Should -BeExactly ''
        @($result.Gpo).Count | Should -Be 1
    }

    It 'counts a GPO of a child domain as a GPO of another domain' {
        Use-Ldap -GpLink @{
            'DC=x' = '[LDAP://cn={D},cn=policies,cn=system,DC=x;0]' +
            '[LDAP://cn={C},cn=policies,cn=system,DC=child,DC=x;0]'
        }

        $result = Get-PrivilegedGpo -Account @('CN=alice,DC=x')

        @($result.Gpo.Name) -join ';' | Should -BeExactly 'GPO cn={D} ({D})'
        $result.Note | Should -BeExactly ' 1 GPOs of another domain were not checked.'
    }

    It 'leaves the objects of the session cache unchanged' {
        $script:cachedGpo = [PSCustomObject]@{
            DistinguishedName = 'cn={D},cn=policies,cn=system,DC=x'; Name = '{D}'; Ace = @()
            Attribute = [ordered]@{ displayName = 'Default' }
        }
        Use-Ldap -GpLink @{ 'DC=x' = '[LDAP://cn={D},cn=policies,cn=system,DC=x;0]' }
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -ParameterFilter {
            $Attribute -contains 'displayName'
        } -MockWith { $script:cachedGpo }

        $null = Get-PrivilegedGpo -Account @('CN=alice,DC=x')
        $second = Get-PrivilegedGpo -Account @('CN=alice,DC=x')

        $second.Gpo[0].Name | Should -BeExactly 'Default ({D})'
        $script:cachedGpo.Name | Should -BeExactly '{D}'
    }

    It 'returns no GPO when nothing is linked' {
        Use-Ldap -GpLink @{}

        $result = Get-PrivilegedGpo -Account @('CN=alice,DC=x')

        @($result.Gpo).Count | Should -Be 0
        $result.Note | Should -BeExactly ''
    }

    It 'lets a failed read throw' {
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith { throw 'LDAP failed' }

        { Get-PrivilegedGpo -Account @('CN=alice,DC=x') } |
            Should -Throw -ExpectedMessage 'LDAP failed'
    }
}
