BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Note {
        param([AllowNull()] [AllowEmptyCollection()] [string[]] $Trustee)
        InModuleScope Maester -Parameters @{ Trustee = $Trustee } {
            param($Trustee)
            Get-MtAnssiAdExchangeNote -Trustee $Trustee
        }
    }
}

Describe 'Get-MtAnssiAdExchangeNote' {
    It 'returns an empty string when no trustee is an Exchange group' -ForEach @(
        @{ Trustee = @('Domain Users', 'Everyone', 'S-1-5-21-1-2-3-1105') }
        @{ Trustee = @('Exchange Server Admins', 'Exchange', 'Exchange Servers Group') }
        @{ Trustee = @() }
        @{ Trustee = $null }
    ) {
        Get-Note -Trustee $Trustee | Should -BeExactly ''
    }

    It 'names the Exchange group <Name>' -ForEach @(
        @{ Name = 'Exchange Trusted Subsystem' }
        @{ Name = 'Exchange Windows Permissions' }
        @{ Name = 'Organization Management' }
        @{ Name = 'Exchange Servers' }
    ) {
        $note = Get-Note -Trustee @('alice', $Name)

        $note | Should -Match ([regex]::Escape($Name))
    }

    It 'matches the group name without regard to case' {
        Get-Note -Trustee @('exchange servers') | Should -Match 'Exchange Servers'
    }

    It 'lists each group once, in a fixed order, whatever the input order' {
        $note = Get-Note -Trustee @(
            'Exchange Servers', 'Organization Management', 'Exchange Servers',
            'Exchange Windows Permissions', 'Exchange Trusted Subsystem')

        $note | Should -Match (
            'Exchange groups among the trustees: Exchange Trusted Subsystem, ' +
            'Exchange Windows Permissions, Organization Management, Exchange Servers\.')
    }

    It 'does not name an Exchange group that is not among the trustees' {
        $note = Get-Note -Trustee @('Exchange Servers')

        $note | Should -Not -Match 'Organization Management'
        $note | Should -Not -Match 'Exchange Windows Permissions'
    }

    It 'explains the cause, the attack and the remedy and links to Microsoft Learn' {
        $note = Get-Note -Trustee @('Exchange Windows Permissions')

        $note | Should -Match 'shared permissions'
        $note | Should -Match 'PrivExchange'
        $note | Should -Match 'split permissions'
        $note | Should -Match (
            'https://learn\.microsoft\.com/exchange/permissions/split-permissions/' +
            'split-permissions')
    }
}
