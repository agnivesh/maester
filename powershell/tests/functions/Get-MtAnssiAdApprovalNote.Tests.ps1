BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-FindingFixture {
        param([string] $Name, [bool] $Approval)
        [PSCustomObject]@{ Name = $Name; ApprovalRequired = $Approval }
    }

    function Get-Note {
        param([object[]] $Finding)
        InModuleScope Maester -Parameters @{ Finding = $Finding } {
            param($Finding)
            Get-MtAnssiAdApprovalNote -Finding $Finding
        }
    }
}

Describe 'Get-MtAnssiAdApprovalNote' {
    It 'returns an empty string when no reported template needs an approval' -ForEach @(
        @{ Finding = @() }
        @{ Finding = @([PSCustomObject]@{ Name = 'A'; ApprovalRequired = $false }) }
    ) {
        Get-Note -Finding $Finding | Should -BeExactly ''
    }

    It 'starts with a blank line and names the templates that need an approval' {
        $note = Get-Note -Finding @(
            Get-FindingFixture -Name 'Open' -Approval $false
            Get-FindingFixture -Name 'Held' -Approval $true
        )

        $note | Should -Match '^\r?\n\r?\nRequests for these templates need manager approval'
        $note | Should -Match 'authorized signatures before a certificate is issued: Held\.'
        $note | Should -Not -Match 'Open'
        $note | Should -Match 'because ANSSI does not exclude them\.$'
    }

    It 'names each template once, in alphabetical order' {
        $note = Get-Note -Finding @(
            Get-FindingFixture -Name 'Zed' -Approval $true
            Get-FindingFixture -Name 'Alpha' -Approval $true
            Get-FindingFixture -Name 'Zed' -Approval $true
        )

        $note | Should -Match 'issued: Alpha, Zed\. They are'
    }
}
