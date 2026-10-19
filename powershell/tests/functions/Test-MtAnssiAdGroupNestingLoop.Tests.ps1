BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-073.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdGroupNestingLoop' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdGroupNestingLoop {
        InModuleScope Maester { Test-MtAnssiAdGroupNestingLoop }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-Group {
        param([string] $Name, [string[]] $Parent = @(), [switch] $Partial)
        $memberOf = [string[]]@($Parent | ForEach-Object { "CN=$_,DC=x" })
        if ($Partial) { $memberOf = $null }
        [PSCustomObject]@{ DistinguishedName = "CN=$Name,DC=x"; Name = $Name; MemberOf = $memberOf }
    }

    function Use-Ad {
        param([object[]] $Group = @())
        $state = [PSCustomObject]@{ Groups = $Group }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdGroupNestingLoop' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when group nesting has no loop' {
            Use-Ad -Group @(Get-Group -Name 'A' -Parent 'B'; Get-Group -Name 'B')

            Test-MtAnssiAdGroupNestingLoop | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -eq 'Group nesting has no loop among the 2 groups.'
            }
        }

        It 'fails when groups are members of each other' {
            Use-Ad -Group @(Get-Group -Name 'A' -Parent 'B'; Get-Group -Name 'B' -Parent 'A')

            Test-MtAnssiAdGroupNestingLoop | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^Group nesting has 1 loop\(s\)'
            }
        }
    }

    Context 'result text' {
        It 'lists each loop with its groups and size' {
            Use-Ad -Group @(
                Get-Group -Name 'Ops' -Parent 'Tier0'
                Get-Group -Name 'Tier0' -Parent 'Helpdesk'
                Get-Group -Name 'Helpdesk' -Parent 'Ops'
                Get-Group -Name 'Self' -Parent 'Self'
            )

            $null = Test-MtAnssiAdGroupNestingLoop

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^Group nesting has 2 loop\(s\)' -and
                $Result -match '(?s)Helpdesk, Ops, Tier0 \| 3 \|.*Self \| 1 \|'
            }
        }

        It 'escapes markdown in a group name' {
            $name = '[click](https://evil.example)|x'
            Use-Ad -Group @(Get-Group -Name $name -Parent $name)

            $null = Test-MtAnssiAdGroupNestingLoop

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Groups category' {
            Use-Ad -Group @(Get-Group -Name 'A')

            $null = Test-MtAnssiAdGroupNestingLoop

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Groups' }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no group was collected' {
            Use-Ad -Group @()

            Test-MtAnssiAdGroupNestingLoop | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'No group was found'
            }
        }

        It 'is skipped when the parent groups of a group were only partly returned' {
            Use-Ad -Group @(Get-Group -Name 'A' -Parent 'B'; Get-Group -Name 'B' -Partial)

            Test-MtAnssiAdGroupNestingLoop | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match 'of 1 group\(s\) were only partly'
            }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdGroupNestingLoop } | Should -Throw 'LDAP bind failed'

        }
    }
}
