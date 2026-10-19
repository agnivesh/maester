BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-068.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdRodcDeniedGroupMember' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdRodcDeniedGroupMember {
        InModuleScope Maester { Test-MtAnssiAdRodcDeniedGroupMember }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    $script:spec = @(
        @{ Name = 'Domain Controllers'; Rid = 516 }
        @{ Name = 'Read-only Domain Controllers'; Rid = 521 }
        @{ Name = 'Group Policy Creator Owners'; Rid = 520 }
        @{ Name = 'Domain Admins'; Rid = 512 }
        @{ Name = 'Cert Publishers'; Rid = 517 }
        @{ Name = 'Schema Admins'; Rid = 518 }
        @{ Name = 'Enterprise Admins'; Rid = 519 }
    )
    $script:groups = foreach ($item in $script:spec) {
        [PSCustomObject]@{
            DistinguishedName = "CN=$($item.Name),CN=Users,DC=contoso,DC=com"
            Name              = $item.Name
            Sid               = [PSCustomObject]@{ Value = "S-1-5-21-1-2-3-$($item.Rid)" }
        }
    }
    $script:krbtgtDn = 'CN=krbtgt,CN=Users,DC=contoso,DC=com'
    $script:users = @([PSCustomObject]@{
            DistinguishedName = $script:krbtgtDn; Name = 'krbtgt'
            Sid               = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-502' }
        })
    $script:dn = @{}
    foreach ($group in $script:groups) { $script:dn[$group.Name] = $group.DistinguishedName }
    $script:dn['krbtgt'] = $script:krbtgtDn
    $script:childMembers = @('Domain Controllers', 'Read-only Domain Controllers',
        'Group Policy Creator Owners', 'Domain Admins', 'Cert Publishers', 'krbtgt' |
        ForEach-Object { $script:dn[$_] })
    $script:rootMembers = @($script:childMembers) +
        @($script:dn['Schema Admins'], $script:dn['Enterprise Admins'])

    function Use-Ad {
        param(
            [AllowNull()] [string[]] $Member = $script:rootMembers,
            [string] $DnsRoot = 'contoso.com',
            [string] $Forest = 'contoso.com',
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3',
            [switch] $NoGroup
        )
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID = $domainSidValue; DnsRoot = $DnsRoot; Forest = $Forest
            }
            Users            = $script:users
            Groups           = $script:groups
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $read = $null
        if (-not $NoGroup) {
            $group = [PSCustomObject]@{ Name = 'Denied' }
            $read = [PSCustomObject]@{ Group = $group; Member = $Member }
        }
        Mock Get-MtAnssiAdGroupMemberDn -ModuleName Maester -MockWith ({ $read }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdRodcDeniedGroupMember' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes in the root domain when every default member is there' {
            Use-Ad

            Test-MtAnssiAdRodcDeniedGroupMember | Should -Be $true
        }

        It 'fails in the root domain without Enterprise Admins' {
            Use-Ad -Member @($rootMembers | Where-Object { $_ -ne $dn['Enterprise Admins'] })

            Test-MtAnssiAdRodcDeniedGroupMember | Should -Be $false
        }

        It 'passes in a child domain without Schema Admins and Enterprise Admins' {
            Use-Ad -Member $childMembers -DnsRoot 'child.contoso.com'

            Test-MtAnssiAdRodcDeniedGroupMember | Should -Be $true
        }

        It 'fails without the krbtgt account' {
            Use-Ad -Member @($rootMembers | Where-Object { $_ -ne $krbtgtDn })

            Test-MtAnssiAdRodcDeniedGroupMember | Should -Be $false
        }

        It 'passes with extra members' {
            Use-Ad -Member (@($rootMembers) + @('CN=Extra,OU=Groups,DC=contoso,DC=com'))

            Test-MtAnssiAdRodcDeniedGroupMember | Should -Be $true
        }
    }

    Context 'member read' {
        It 'reads the members of the domain RID 572 group with the collected data' {
            Use-Ad

            $null = Test-MtAnssiAdRodcDeniedGroupMember

            Should -Invoke Get-MtAnssiAdGroupMemberDn -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $Sid -eq 'S-1-5-21-1-2-3-572' -and @($Group).Count -eq 7 -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }
    }

    Context 'result text' {
        It 'says the group is complete in the root domain' {
            Use-Ad

            $null = Test-MtAnssiAdRodcDeniedGroupMember

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'holds all its default members\.$'
            }
        }

        It 'says what was not checked in a child domain' {
            Use-Ad -Member $childMembers -DnsRoot 'child.contoso.com'

            $null = Test-MtAnssiAdRodcDeniedGroupMember

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'holds all its default members\. Schema Admins and Enterprise Admins'
            }
        }

        It 'names the missing members in order' {
            Use-Ad -Member @($dn['Domain Controllers'], $krbtgtDn)

            $null = Test-MtAnssiAdRodcDeniedGroupMember

            Should -Invoke @detail -ParameterFilter {
                $Result -match ('missing default members: Read-only Domain Controllers, ' +
                    'Group Policy Creator Owners, Domain Admins, Cert Publishers, Schema Admins, ' +
                    'Enterprise Admins\.')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Domain, Users and Groups categories' {
            Use-Ad

            $null = Test-MtAnssiAdRodcDeniedGroupMember

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 3 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Groups'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the group is not in the collected data' {
            Use-Ad -NoGroup

            Test-MtAnssiAdRodcDeniedGroupMember | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'Denied RODC'
            }
        }

        It 'is skipped without reading when the domain SID is missing' {
            Use-Ad -DomainSid $null

            Test-MtAnssiAdRodcDeniedGroupMember | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdGroupMemberDn -ModuleName Maester -Times 0 -Exactly
        }

        It 'lets the exception reach the engine when the members cannot be read' {
            Use-Ad
            Mock Get-MtAnssiAdGroupMemberDn -ModuleName Maester `
                -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdRodcDeniedGroupMember } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdRodcDeniedGroupMember } | Should -Throw 'LDAP bind failed'

        }
    }
}
