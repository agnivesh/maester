BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-071.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdSidHistoryPresent' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdSidHistoryPresent {
        InModuleScope Maester { Test-MtAnssiAdSidHistoryPresent }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-ItemFixture {
        param([string] $Name = 'alice', [object[]] $SidHistory = @(), [object] $LastLogon = $null)
        [PSCustomObject]@{
            SamAccountName = $Name
            SidHistory     = $SidHistory
            LastLogonDate  = $LastLogon
        }
    }

    function Use-Ad {
        param([object[]] $User = @(), [object[]] $Computer = @(), [object[]] $Group = @())
        $state = [PSCustomObject]@{ Users = $User; Computers = $Computer; Groups = $Group }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdSidHistoryPresent' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when no object has a SID history' {
            Use-Ad -User @(Get-ItemFixture) -Computer @(Get-ItemFixture -Name 'pc$') `
                -Group @(Get-ItemFixture -Name 'g1')

            Test-MtAnssiAdSidHistoryPresent | Should -BeTrue
        }

        It 'fails for a user with a SID history' {
            Use-Ad -User @(Get-ItemFixture -SidHistory @('S-1-5-21-1-2-3-1104'))

            Test-MtAnssiAdSidHistoryPresent | Should -Be $false
        }

        It 'fails for a computer with a SID history' {
            Use-Ad -User @(Get-ItemFixture) -Computer @(
                Get-ItemFixture -Name 'pc$' -SidHistory @('S-1-5-21-1-2-3-1104')
            )

            Test-MtAnssiAdSidHistoryPresent | Should -Be $false
        }

        It 'fails for a group with a SID history' {
            Use-Ad -User @(Get-ItemFixture) -Group @(
                Get-ItemFixture -Name 'g1' -SidHistory @('S-1-5-21-1-2-3-1104')
            )

            Test-MtAnssiAdSidHistoryPresent | Should -Be $false
        }

        It 'counts every kind of SID, not only the privileged ones' {
            Use-Ad -User @(Get-ItemFixture -SidHistory @('S-1-5-21-1-2-3-99999'))

            Test-MtAnssiAdSidHistoryPresent | Should -Be $false
        }
    }

    Context 'result text' {
        It 'counts the objects when the test passes' {
            Use-Ad -User @(Get-ItemFixture) -Computer @(Get-ItemFixture -Name 'pc$') `
                -Group @(Get-ItemFixture -Name 'g1')

            $null = Test-MtAnssiAdSidHistoryPresent

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^None of the 3 users, computers and groups has a SID history\.$'
            }
        }

        It 'lists the objects with type, SID history and last logon, sorted by type and name' {
            $history = @('S-1-5-21-1-2-3-1104', 'S-1-5-21-4-5-6-1104')
            Use-Ad -User @(
                Get-ItemFixture -Name 'aaa' -SidHistory $history -LastLogon ([datetime]'2026-08-15')
            ) -Computer @(Get-ItemFixture -Name 'fine$') -Group @(
                Get-ItemFixture -Name 'zgrp' -SidHistory @('S-1-5-21-1-2-3-1200')
            )

            $null = Test-MtAnssiAdSidHistoryPresent

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^2 of 3 users, computers and groups' -and
                $Result -match '(?s)Group \| zgrp \| S-1-5-21-1-2-3-1200 \| n/a \|.*' +
                'User \| aaa \| S-1-5-21-1-2-3-1104, S-1-5-21-4-5-6-1104 \| 2026-08-15 \|' -and
                $Result -notmatch 'fine'
            }
        }

        It 'escapes markdown in the object name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -User @(Get-ItemFixture -Name $evil -SidHistory @('S-1-5-21-1-2-3-1104'))

            $null = Test-MtAnssiAdSidHistoryPresent

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Users, Computers and Groups categories' {
            Use-Ad -User @(Get-ItemFixture)

            $null = Test-MtAnssiAdSidHistoryPresent

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 3 -and $Categories -contains 'Users' -and
                $Categories -contains 'Computers' -and $Categories -contains 'Groups'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when there is no data' {
            Use-Ad

            Test-MtAnssiAdSidHistoryPresent | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match 'user, computer or group'
            }
        }

        It 'runs when only groups are collected' {
            Use-Ad -Group @(Get-ItemFixture -Name 'g1')

            Test-MtAnssiAdSidHistoryPresent | Should -BeTrue
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdSidHistoryPresent } | Should -Throw 'LDAP bind failed'

        }
    }

    It 'is skipped when the <Collection> collection was not returned' -ForEach @(
        @{ Collection = 'Users' }
        @{ Collection = 'Computers' }
        @{ Collection = 'Groups' }
    ) {
        $props = [ordered]@{ Users = @(); Computers = @(); Groups = @() }
        $props[$Collection] = $null
        $state = [PSCustomObject]$props
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

        Test-MtAnssiAdSidHistoryPresent | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
