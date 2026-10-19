BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:groupFilter = '(&(objectClass=msDFSR-ReplicationGroup)(cn=Domain System Volume))'
    $script:localFilter = '(|(objectClass=msDFSR-LocalSettings)(objectClass=msDFSR-Subscriber)' +
    '(objectClass=msDFSR-Subscription))'

    function Use-Ldap {
        param([switch] $NoGroup)
        $script:noGroup = $NoGroup.IsPresent
        Mock Get-MtAnssiAdSearchSecurity -ModuleName Maester -MockWith {
            if ($Filter -eq $script:groupFilter) {
                if (-not $script:noGroup) {
                    [PSCustomObject]@{ DistinguishedName = ('CN=Domain System' +
                        ' Volume,CN=DFSR-GlobalSettings,CN=System,DC=x') }
                }
            } elseif ($Filter -eq '(objectClass=*)') {
                foreach ($base in $SearchBase) {
                    [PSCustomObject]@{ DistinguishedName = "group:$base" }
                }
            } else {
                foreach ($base in $SearchBase) {
                    [PSCustomObject]@{ DistinguishedName = "local:$base" }
                }
            }
        }
    }

    function Get-Dfsr {
        param([object[]] $Computer)
        $evidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        InModuleScope Maester -Parameters @{ Computer = $Computer; Evidence = $evidence } {
            param($Computer, $Evidence)
            @(Get-MtAnssiAdDfsrSysvolObject -DomainDn 'DC=x' -Computer $Computer `
                -DomainController @() `
                    -ProtocolEvidence $Evidence)
        }
    }

    $script:computers = @(
        [PSCustomObject]@{
            DistinguishedName = 'CN=DC1,OU=Domain Controllers,DC=x'
            PrimaryGroupId = 516
        }
        [PSCustomObject]@{
            DistinguishedName = 'CN=RODC1,OU=Domain Controllers,DC=x'
            PrimaryGroupId = 521
        }
        [PSCustomObject]@{ DistinguishedName = 'CN=PC1,DC=x'; PrimaryGroupId = 515 }
    )
}

Describe 'Get-MtAnssiAdDfsrSysvolObject' {
    It 'reads the replication group tree and the local settings of every domain controller' {
        Use-Ldap

        $result = Get-Dfsr -Computer $script:computers

        @($result.DistinguishedName) -join ';' | Should -BeExactly (
            'group:CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=x;' +
            'local:CN=DC1,OU=Domain Controllers,DC=x;local:CN=RODC1,OU=Domain Controllers,DC=x')
        Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            ($SearchBase -join ';') -eq 'CN=System,DC=x' -and $Scope -eq 'Subtree' -and
            $Filter -eq $script:groupFilter -and $ProtocolEvidence.ResolvedServer -eq 'dc1'
        }
        Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $Scope -eq 'Subtree' -and $Filter -eq '(objectClass=*)' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
        }
        Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $Scope -eq 'Subtree' -and $Filter -eq $script:localFilter -and
            ($SearchBase -join ';') -eq ('CN=DC1,OU=Domain Controllers,DC=x;CN=RODC1,OU=Domain' +
                ' Controllers,DC=x') -and
            $ProtocolEvidence.ResolvedServer -eq 'dc1'
        }
    }

    It 'reads only the local settings when SYSVOL has no DFSR replication group' {
        Use-Ldap -NoGroup

        $result = Get-Dfsr -Computer $script:computers

        @($result | Where-Object { $_.DistinguishedName -like 'group:*' }).Count | Should -Be 0
        Should -Invoke Get-MtAnssiAdSearchSecurity -ModuleName Maester -Times 0 -Exactly `
            -ParameterFilter {
            $Filter -eq '(objectClass=*)'
        }
    }

    It 'reads no local settings without domain controllers' {
        Use-Ldap

        $result = Get-Dfsr -Computer @($script:computers[2])

        @($result.DistinguishedName) -join ';' |
            Should -BeExactly 'group:CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=x'
    }

    It 'lets a failed search throw' {
        Mock Get-MtAnssiAdSearchSecurity -ModuleName Maester -MockWith { throw 'LDAP failed' }

        { Get-Dfsr -Computer $script:computers } | Should -Throw -ExpectedMessage 'LDAP failed'
    }
}
