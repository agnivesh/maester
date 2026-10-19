BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Select-Untrusted {
        param([AllowNull()] [string[]] $Sid, [string[]] $Trusted = @('S-1-5-18'))
        InModuleScope Maester -Parameters @{ Sid = $Sid; Trusted = $Trusted } {
            param($Sid, $Trusted)
            $set = [System.Collections.Generic.HashSet[string]]::new(
                [string[]]$Trusted, [System.StringComparer]::OrdinalIgnoreCase)
            @(Select-MtAnssiAdUntrustedSid -Sid $Sid -TrustedSid $set)
        }
    }
}

Describe 'Select-MtAnssiAdUntrustedSid' {
    It 'returns the SIDs that are not in the trusted set, in order' {
        $result = Select-Untrusted -Sid @('S-1-5-21-1-2-3-1106', 'S-1-5-18', 'S-1-5-21-1-2-3-1105')

        $result -join ',' | Should -BeExactly 'S-1-5-21-1-2-3-1106,S-1-5-21-1-2-3-1105'
    }

    It 'trusts the group with RID <Rid> of any domain' -ForEach @(
        @{ Rid = 498 }
        @{ Rid = 518 }
        @{ Rid = 519 }
        @{ Rid = 527 }
    ) {
        @(Select-Untrusted -Sid @("S-1-5-21-9-9-9-$Rid")).Count | Should -Be 0
    }

    It 'does not trust <Sid>' -ForEach @(
        @{ Sid = 'S-1-5-21-9-9-9-520' }
        @{ Sid = 'S-1-5-21-9-9-9-5190' }
        @{ Sid = 'S-1-5-21-9-9-9-1519' }
        @{ Sid = 'S-1-5-21-9-9-519' }
        @{ Sid = 'S-1-5-32-519' }
        @{ Sid = 'X-S-1-5-21-9-9-9-519' }
    ) {
        (Select-Untrusted -Sid @($Sid)) -join ',' | Should -BeExactly $Sid
    }

    It 'drops empty values' {
        @(Select-Untrusted -Sid @('', $null)).Count | Should -Be 0
        @(Select-Untrusted -Sid $null).Count | Should -Be 0
    }
}
