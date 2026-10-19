BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-FindingFixture {
        param([string] $Name, [bool] $Trusted)
        [PSCustomObject]@{ Name = $Name; Trusted = $Trusted }
    }

    function Get-Note {
        param([object[]] $Finding)
        InModuleScope Maester -Parameters @{ Finding = $Finding } {
            param($Finding)
            Get-MtAnssiAdPublicationNote -Finding $Finding
        }
    }
}

Describe 'Get-MtAnssiAdPublicationNote' {
    It 'returns an empty string when no trusted CA publishes a reported template' -ForEach @(
        @{ Finding = @() }
        @{ Finding = @([PSCustomObject]@{ Name = 'A'; Trusted = $false }) }
    ) {
        Get-Note -Finding $Finding | Should -BeExactly ''
    }

    It 'starts with a blank line and names the templates that a trusted CA publishes' {
        $note = Get-Note -Finding @(
            Get-FindingFixture -Name 'Quiet' -Trusted $false
            Get-FindingFixture -Name 'Live' -Trusted $true
        )

        $note | Should -Match '^\r?\n\r?\nA CA trusted for logon publishes these templates'
        $note | Should -Match 'so the attack works today: Live\.$'
        $note | Should -Not -Match 'Quiet'
    }

    It 'names each template once, in alphabetical order' {
        $note = Get-Note -Finding @(
            Get-FindingFixture -Name 'Zed' -Trusted $true
            Get-FindingFixture -Name 'Alpha' -Trusted $true
            Get-FindingFixture -Name 'Zed' -Trusted $true
        )

        $note | Should -Match 'works today: Alpha, Zed\.$'
    }
}
