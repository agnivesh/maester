BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Note {
        param([AllowNull()] [object[]] $Unresolved)
        InModuleScope Maester -Parameters @{ Unresolved = $Unresolved } {
            param($Unresolved)
            Format-MtAnssiAdUnresolvedNote -Unresolved $Unresolved
        }
    }

    function Get-UnresolvedFixture {
        param([string] $Dn)
        [PSCustomObject]@{ DistinguishedName = $Dn; Group = @('Domain Admins') }
    }
}

Describe 'Format-MtAnssiAdUnresolvedNote' {
    It 'counts the members that were not checked, after a leading space' {
        $members = @((Get-UnresolvedFixture -Dn 'CN=a'), (Get-UnresolvedFixture -Dn 'CN=b'))
        $note = Get-Note -Unresolved $members

        $note | Should -BeExactly (' The protected groups also hold 2 member(s) outside the ' +
            'collected data, such as accounts or groups from another domain. Those were not ' +
            'checked.')
    }

    It 'returns an empty string when every member was checked' -ForEach @(
        @{ Case = 'an empty list'; Unresolved = @() }
        @{ Case = 'no list'; Unresolved = $null }
    ) {
        Get-Note -Unresolved $Unresolved | Should -BeExactly ''
    }
}
