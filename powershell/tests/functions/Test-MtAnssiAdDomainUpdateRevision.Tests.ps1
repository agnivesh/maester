BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-038.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDomainUpdateRevision' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDomainUpdateRevision {
        InModuleScope Maester { Test-MtAnssiAdDomainUpdateRevision }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Use-Domain {
        param([AllowNull()] [object] $Revision = 16, [string] $Name = 'contoso.com')
        $state = [PSCustomObject]@{
            Domain = [PSCustomObject]@{ Name = $Name; DomainUpdateRevision = $Revision }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }

    function Use-Assessment {
        param([switch] $Broad, [switch] $Unreadable)
        $rows = @()
        if ($Broad) {
            $rows = @([PSCustomObject]@{
                    Group = 'Enterprise Key Admins'; Sid = 'S-1-5-21-1-2-3-527'
                    Mask = '0x10000000'; ObjectType = 'all'
                })
        }
        $assessment = [PSCustomObject]@{ Readable = -not $Unreadable; Broad = $rows }
        Mock Get-MtAnssiAdKeyAdminsAssessment -ModuleName Maester `
            -MockWith ({ $assessment }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDomainUpdateRevision' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'fails at revision 15 when a Key Admins group holds a broad right' {
            Use-Domain -Revision 15
            Use-Assessment -Broad

            Test-MtAnssiAdDomainUpdateRevision | Should -Be $false
        }

        It 'passes at revision 15 when the Key Admins rights are the narrow ones' {
            Use-Domain -Revision 15
            Use-Assessment

            Test-MtAnssiAdDomainUpdateRevision | Should -Be $true
        }

        It 'passes at revision <Revision> without reading the permissions' -ForEach @(
            @{ Revision = 16 }
            @{ Revision = 17 }
            @{ Revision = 14 }
            @{ Revision = 10 }
        ) {
            Use-Domain -Revision $Revision
            Use-Assessment -Broad

            Test-MtAnssiAdDomainUpdateRevision | Should -Be $true

            Should -Invoke Get-MtAnssiAdKeyAdminsAssessment -ModuleName Maester -Times 0 -Exactly
        }
    }

    Context 'result text' {
        It 'shows the revision when the test passes' {
            Use-Domain -Revision 16
            Use-Assessment

            $null = Test-MtAnssiAdDomainUpdateRevision

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'of contoso\.com is at revision 16\.'
            }
        }

        It 'says the permissions are narrow when revision 15 passes' {
            Use-Domain -Revision 15
            Use-Assessment

            $null = Test-MtAnssiAdDomainUpdateRevision

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'of contoso\.com is at revision 15' -and
                $Result -match 'msDS-KeyCredentialLink' -and $Result -match 'revision 16' -and
                $Result -match 'still advised'
            }
        }

        It 'names the broad entry and the fix when the test fails' {
            Use-Domain -Revision 15
            Use-Assessment -Broad

            $null = Test-MtAnssiAdDomainUpdateRevision

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'of contoso\.com is at revision 15' -and
                $Result -match 'Enterprise Key Admins \| S-1-5-21-1-2-3-527 \| 0x10000000' -and
                $Result -match 'revision 16'
            }
        }

        It 'escapes markdown in the domain name' {
            Use-Domain -Revision 15 -Name '[click](https://evil.example)'
            Use-Assessment -Broad

            $null = Test-MtAnssiAdDomainUpdateRevision

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Domain category' {
            Use-Domain
            Use-Assessment

            $null = Test-MtAnssiAdDomainUpdateRevision

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Domain' }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when the revision could not be read' {
            Use-Domain -Revision $null

            Test-MtAnssiAdDomainUpdateRevision | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'revision'
            }
        }

        It 'is skipped when the permissions of the domain root could not be read' {
            Use-Domain -Revision 15
            Use-Assessment -Unreadable

            Test-MtAnssiAdDomainUpdateRevision | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'permissions'
            }
        }

        It 'lets the exception reach the engine when reading the permissions fails' {
            Use-Domain -Revision 15
            Mock Get-MtAnssiAdKeyAdminsAssessment -ModuleName Maester `
                -MockWith { throw 'bind failed' }

            { Test-MtAnssiAdDomainUpdateRevision } | Should -Throw 'bind failed'

        }

        It 'is skipped when the domain was not collected' {
            $state = [PSCustomObject]@{ Domain = $null }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDomainUpdateRevision | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter { $SkippedBecause -eq 'Custom' }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDomainUpdateRevision } | Should -Throw 'LDAP bind failed'

        }
    }
}
