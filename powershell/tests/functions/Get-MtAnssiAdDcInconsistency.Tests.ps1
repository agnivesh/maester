BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-ControllerFixture {
        param(
            [string] $Type = 'Writable',
            [int] $Flags = 532480,
            [switch] $WithEntry
        )
        $entry = $null
        if ($WithEntry) {
            $entry = [PSCustomObject]@{ Name = 'DC1' }
        }
        [PSCustomObject]@{
            Type             = $Type
            Computer         = [PSCustomObject]@{ Name = 'DC1'; UserAccountControl = $Flags }
            DomainController = $entry
        }
    }

    function Get-TypicalReadOnlyFixture {
        param([switch] $WithEntry)
        Get-ControllerFixture -Type ReadOnly -Flags 83890176 -WithEntry:$WithEntry
    }

    function Find-Problem {
        param([object] $Controller)
        InModuleScope Maester -Parameters @{ Controller = $Controller } {
            , @(Get-MtAnssiAdDcInconsistency -Controller @($Controller))
        }
    }
}

Describe 'Get-MtAnssiAdDcInconsistency' {
    Context 'writable domain controllers' {
        It 'finds nothing for the typical value 532480 with an entry' {
            $problems = Find-Problem -Controller (Get-ControllerFixture -WithEntry)

            $problems.Count | Should -Be 0
        }

        It 'accepts extra flags on top of the required ones' {
            $flags = 532480 + 0x10000 + 0x200000
            $problems = Find-Problem -Controller (Get-ControllerFixture -Flags $flags -WithEntry)

            $problems.Count | Should -Be 0
        }

        It 'reports <Flag> when it is missing' -ForEach @(
            @{ Flag = 'SERVER_TRUST_ACCOUNT'; Flags = 0x80000 }
            @{ Flag = 'TRUSTED_FOR_DELEGATION'; Flags = 0x2000 }
        ) {
            $problems = Find-Problem -Controller (Get-ControllerFixture -Flags $Flags -WithEntry)

            $problems.Count | Should -Be 1
            $problems[0].Problem | Should -Match "lacks the $Flag flag"
            $problems[0].Name | Should -Be 'DC1'
            $problems[0].Type | Should -Be 'Writable'
        }

        It 'reports both flags when userAccountControl is zero' {
            $problems = Find-Problem -Controller (Get-ControllerFixture -Flags 0 -WithEntry)

            $problems.Count | Should -Be 2
        }

        It 'reports a missing domain controller entry' {
            $problems = Find-Problem -Controller (Get-ControllerFixture)

            $problems.Count | Should -Be 1
            $problems[0].Problem | Should -Match 'No domain controller entry .* nTDSDSA'
        }

        It 'reports every problem of one controller' {
            $problems = Find-Problem -Controller (Get-ControllerFixture -Flags 512)

            $problems.Count | Should -Be 3
        }
    }

    Context 'read-only domain controllers' {
        It 'finds nothing for the typical value 83890176 without an entry' {
            $problems = Find-Problem -Controller (Get-TypicalReadOnlyFixture)

            $problems.Count | Should -Be 0
        }

        It 'reports <Flag> when it is missing' -ForEach @(
            @{ Flag = 'PARTIAL_SECRETS_ACCOUNT'; Flags = 0x1000000 + 0x1000 }
            @{ Flag = 'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION'; Flags = 0x4000000 + 0x1000 }
            @{ Flag = 'WORKSTATION_TRUST_ACCOUNT'; Flags = 0x4000000 + 0x1000000 }
        ) {
            $controller = Get-ControllerFixture -Type ReadOnly -Flags $Flags
            $problems = Find-Problem -Controller $controller

            $problems.Count | Should -Be 1
            $problems[0].Problem | Should -Match "lacks the $Flag flag"
            $problems[0].Type | Should -Be 'ReadOnly'
        }

        It 'reports a writable entry that points to the read-only controller' {
            $problems = Find-Problem -Controller (Get-TypicalReadOnlyFixture -WithEntry)

            $problems.Count | Should -Be 1
            $problems[0].Problem | Should -Match 'writable domain controller entry'
        }

        It 'does not ask a read-only controller for the writable flags' {
            $problems = Find-Problem -Controller (Get-TypicalReadOnlyFixture)

            $problems | Where-Object { $_.Problem -match 'SERVER_TRUST_ACCOUNT' } |
                Should -BeNullOrEmpty
        }
    }

    It 'returns an empty array without controllers' {
        $problems = InModuleScope Maester {
            , @(Get-MtAnssiAdDcInconsistency -Controller @())
        }

        $problems.Count | Should -Be 0
    }

    It 'accepts a text value for userAccountControl' {
        $controller = Get-ControllerFixture -WithEntry
        $controller.Computer.UserAccountControl = '532480'

        (Find-Problem -Controller $controller).Count | Should -Be 0
    }
}
