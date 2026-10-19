BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-053.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdSidHistoryDangerous' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdSidHistoryDangerous {
        InModuleScope Maester { Test-MtAnssiAdSidHistoryDangerous }
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

Describe 'Test-MtAnssiAdSidHistoryDangerous' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It '<Name>' -ForEach @(
            @{ Name = 'passes when nothing has a SID history'; Sid = @(); Expected = $true }
            @{ Name = 'passes for an ordinary migrated SID'; Sid = @('S-1-5-21-1-2-3-1104')
                Expected = $true }
            @{ Name = 'passes for the first ordinary RID'; Sid = @('S-1-5-21-1-2-3-1000')
                Expected = $true }
            @{ Name = 'fails for the last reserved RID'; Sid = @('S-1-5-21-1-2-3-999')
                Expected = $false }
            @{ Name = 'fails for Domain Admins'; Sid = @('S-1-5-21-1-2-3-512'); Expected = $false }
            @{ Name = 'fails for Enterprise Admins'; Sid = @('S-1-5-21-1-2-3-519')
                Expected = $false }
            @{ Name = 'fails for the Administrator account'; Sid = @('S-1-5-21-1-2-3-500')
                Expected = $false }
            @{ Name = 'fails for Everyone'; Sid = @('S-1-1-0'); Expected = $false }
            @{ Name = 'fails for the built-in Administrators group'; Sid = @('S-1-5-32-544')
                Expected = $false }
            @{ Name = 'fails when one of several values is dangerous'
                Sid = @('S-1-5-21-1-2-3-1104', 'S-1-5-21-1-2-3-519'); Expected = $false }
        ) {
            Use-Ad -User @(Get-ItemFixture -SidHistory $Sid)

            Test-MtAnssiAdSidHistoryDangerous | Should -Be $Expected
        }

        It 'checks computers and groups as well as users' {
            Use-Ad -User @(Get-ItemFixture) -Computer @(
                Get-ItemFixture -Name 'pc$' -SidHistory @('S-1-5-21-1-2-3-1104')
            ) -Group @(Get-ItemFixture -Name 'g1' -SidHistory @('S-1-5-21-1-2-3-518'))

            Test-MtAnssiAdSidHistoryDangerous | Should -Be $false
        }
    }

    Context 'result text' {
        It 'counts the objects with a SID history when the test passes' {
            Use-Ad -User @(
                Get-ItemFixture -Name 'a' -SidHistory @('S-1-5-21-1-2-3-1104')
                Get-ItemFixture -Name 'b'
            ) -Group @(Get-ItemFixture -Name 'g1' -SidHistory @('S-1-5-21-1-2-3-1105'))

            $null = Test-MtAnssiAdSidHistoryDangerous

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^None of the 2 users, computers and groups with a SID history'
            }
        }

        It 'lists each dangerous SID with its risk, and counts the objects once' {
            $history = @('S-1-5-21-1-2-3-519', 'S-1-5-32-544', 'S-1-5-21-1-2-3-1104')
            Use-Ad -User @(Get-ItemFixture -Name 'bob' -SidHistory $history) -Group @(
                Get-ItemFixture -Name 'grp' -SidHistory @('S-1-1-0')
                Get-ItemFixture -Name 'fine' -SidHistory @('S-1-5-21-1-2-3-1104')
            )

            $null = Test-MtAnssiAdSidHistoryDangerous

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^2 users, computers and groups' -and
                $Result -match 'User \| bob \| S-1-5-21-1-2-3-519 \| Privileged domain SID \|' -and
                $Result -match 'User \| bob \| S-1-5-32-544 \| Well-known SID \|' -and
                $Result -match 'Group \| grp \| S-1-1-0 \| Well-known SID \|' -and
                $Result -notmatch '1104' -and $Result -notmatch 'fine'
            }
        }

        It 'sorts privileged domain SIDs before well-known SIDs, then by type and name' {
            Use-Ad -User @(
                Get-ItemFixture -Name 'a' -SidHistory @('S-1-1-0')
                Get-ItemFixture -Name 'z' -SidHistory @('S-1-5-21-1-2-3-512')
            )

            $null = Test-MtAnssiAdSidHistoryDangerous

            Should -Invoke @detail -ParameterFilter {
                $Result -match '(?s)User \| z \| .*Privileged domain SID.*User \| a \| .*Well-known'
            }
        }

        It 'sorts by type, then name, within the same risk' {
            Use-Ad -User @(Get-ItemFixture -Name 'aaa' -SidHistory @('S-1-1-0')) -Group @(
                Get-ItemFixture -Name 'zzz' -SidHistory @('S-1-1-0')
            )

            $null = Test-MtAnssiAdSidHistoryDangerous

            Should -Invoke @detail -ParameterFilter {
                $Result -match '(?s)Group \| zzz \|.*User \| aaa \|'
            }
        }

        It 'shows the last logon, or n/a when there is none' {
            Use-Ad -User @(Get-ItemFixture -Name 'bob' -SidHistory @('S-1-1-0') `
                    -LastLogon ([datetime]'2026-07-04')) -Group @(
                Get-ItemFixture -Name 'grp' -SidHistory @('S-1-1-0')
            )

            $null = Test-MtAnssiAdSidHistoryDangerous

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'Group \| grp \| S-1-1-0 \| Well-known SID \| n/a \|' -and
                $Result -match 'User \| bob \| S-1-1-0 \| Well-known SID \| 2026-07-04 \|'
            }
        }

        It 'escapes markdown in the object name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -User @(Get-ItemFixture -Name $evil -SidHistory @('S-1-1-0'))

            $null = Test-MtAnssiAdSidHistoryDangerous

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Users, Computers and Groups categories' {
            Use-Ad -User @(Get-ItemFixture)

            $null = Test-MtAnssiAdSidHistoryDangerous

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

            Test-MtAnssiAdSidHistoryDangerous | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match 'user, computer or group'
            }
        }

        It 'runs when only groups are collected' {
            Use-Ad -Group @(Get-ItemFixture -Name 'g1' -SidHistory @('S-1-1-0'))

            Test-MtAnssiAdSidHistoryDangerous | Should -Be $false
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdSidHistoryDangerous } | Should -Throw 'LDAP bind failed'

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

        Test-MtAnssiAdSidHistoryDangerous | Should -BeNullOrEmpty

        $filter = [scriptblock]::Create(
            "`$SkippedBecause -eq 'Custom' -and `$SkippedCustomReason -match '$Collection'")
        Should -Invoke @detail -ParameterFilter $filter
    }
}
