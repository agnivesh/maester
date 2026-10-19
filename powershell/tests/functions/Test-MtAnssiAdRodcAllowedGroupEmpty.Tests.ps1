BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-067.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdRodcAllowedGroupEmpty' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdRodcAllowedGroupEmpty {
        InModuleScope Maester { Test-MtAnssiAdRodcAllowedGroupEmpty }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    $script:bobDn = 'CN=Bob,OU=Branch,DC=contoso,DC=com'
    $script:aliceDn = 'CN=Alice,OU=Branch,DC=contoso,DC=com'
    $script:users = @(
        [PSCustomObject]@{
            DistinguishedName = $script:bobDn; Name = 'Bob'
            Sid               = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1201' }
        }
        [PSCustomObject]@{
            DistinguishedName = $script:aliceDn; Name = 'Alice'
            Sid               = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1202' }
        }
    )

    function Use-Ad {
        param(
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3',
            [AllowNull()] [string[]] $Member = @(),
            [switch] $NoGroup
        )
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{ DomainSID = $domainSidValue }
            Users            = $script:users
            Computers        = @()
            Groups           = @([PSCustomObject]@{ Name = 'G1' })
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $read = $null
        if (-not $NoGroup) {
            $group = [PSCustomObject]@{ Name = 'Allowed' }
            $read = [PSCustomObject]@{ Group = $group; Member = $Member }
        }
        Mock Get-MtAnssiAdGroupMemberDn -ModuleName Maester -MockWith ({ $read }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdRodcAllowedGroupEmpty' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when the group is empty' {
            Use-Ad -Member @()

            Test-MtAnssiAdRodcAllowedGroupEmpty | Should -Be $true

            Should -Invoke @detail -ParameterFilter { $Result -match 'is empty' }
        }

        It 'fails when the group has a member' {
            Use-Ad -Member @($bobDn)

            Test-MtAnssiAdRodcAllowedGroupEmpty | Should -Be $false
        }
    }

    Context 'member read' {
        It 'reads the members of the domain RID 571 group with the collected data' {
            Use-Ad

            $null = Test-MtAnssiAdRodcAllowedGroupEmpty

            Should -Invoke Get-MtAnssiAdGroupMemberDn -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                $Sid -eq 'S-1-5-21-1-2-3-571' -and @($Group)[0].Name -eq 'G1' -and
                $ProtocolEvidence.ResolvedServer -eq 'dc1'
            }
        }
    }

    Context 'result text' {
        It 'counts and lists the members by name with their SID' {
            Use-Ad -Member @($bobDn, 'CN=Far,DC=other,DC=com', $aliceDn)

            $null = Test-MtAnssiAdRodcAllowedGroupEmpty

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match 'has 3 member\(s\)' -and
                $text -match ('(?s)Alice \| S-1-5-21-1-2-3-1202 \|.*' +
                    'Bob \| S-1-5-21-1-2-3-1201 \|.*CN=Far,DC=other,DC=com \|')
            }
        }

        It 'escapes markdown in a member name' {
            Use-Ad -Member @('CN=[click](https://evil.example)|x,DC=other,DC=com')

            $null = Test-MtAnssiAdRodcAllowedGroupEmpty

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Domain, Users, Computers and Groups categories' {
            Use-Ad

            $null = Test-MtAnssiAdRodcAllowedGroupEmpty

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the group is not in the collected data' {
            Use-Ad -NoGroup

            Test-MtAnssiAdRodcAllowedGroupEmpty | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'Allowed RODC'
            }
        }

        It 'is skipped without reading when the domain SID is missing' {
            Use-Ad -DomainSid $null

            Test-MtAnssiAdRodcAllowedGroupEmpty | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdGroupMemberDn -ModuleName Maester -Times 0 -Exactly
            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when the members cannot be read' {
            Use-Ad
            Mock Get-MtAnssiAdGroupMemberDn -ModuleName Maester `
                -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdRodcAllowedGroupEmpty } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdRodcAllowedGroupEmpty } | Should -Throw 'LDAP bind failed'

        }
    }
}
