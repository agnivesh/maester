BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Map {
        param([string] $Server)
        $evidence = [PSCustomObject]@{ ResolvedServer = $Server }
        InModuleScope Maester -Parameters @{ Evidence = $evidence } {
            param($Evidence)
            Get-MtAnssiAdMemberMapCache -ProtocolEvidence $Evidence
        }
    }
}

Describe 'Get-MtAnssiAdMemberMapCache' {
    BeforeEach {
        Clear-MtADCache
    }

    It 'returns the same map for the same server' {
        $first = Get-Map -Server 'dc1'
        $first['CN=G,DC=x'] = @('CN=a,DC=x')

        $second = Get-Map -Server 'dc1'

        [object]::ReferenceEquals($first, $second) | Should -Be $true
        $second['CN=G,DC=x'] | Should -Be @('CN=a,DC=x')
    }

    It 'returns a separate map for another server' {
        $first = Get-Map -Server 'dc1'
        $first['CN=G,DC=x'] = @('CN=a,DC=x')

        $other = Get-Map -Server 'dc2'

        $other.Count | Should -Be 0
    }

    It 'starts empty again after Clear-MtADCache' {
        $first = Get-Map -Server 'dc1'
        $first['CN=G,DC=x'] = @('CN=a,DC=x')
        Clear-MtADCache

        (Get-Map -Server 'dc1').Count | Should -Be 0
    }
}
