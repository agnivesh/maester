BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-State {
        param([AllowNull()] [object] $ProtocolEvidence = 'evidence',
            [string] $Dn = 'DC=contoso,DC=com')
        [PSCustomObject]@{
            Domain = [PSCustomObject]@{ DistinguishedName = $Dn }
            ProtocolEvidence = $ProtocolEvidence
        }
    }

    function Get-Assessment {
        param([object] $State)
        InModuleScope Maester -Parameters @{ State = $State } {
            param($State)
            Get-MtAnssiAdKeyAdminsAssessment -AdState $State
        }
    }

    function Get-AceFixture {
        param([string] $Sid = 'S-1-5-21-1-2-3-527', [uint32] $Mask = 0x30,
            [string] $ObjectType = '5b47d60f-6090-40b2-9f37-2a4de88f3063')
        [PSCustomObject]@{
            Type = 'Allow'; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $false; IsInherited = $false; Sid = $Sid
        }
    }
}

Describe 'Get-MtAnssiAdKeyAdminsAssessment' {
    It 'reads the permissions of the domain root through the protocol evidence' {
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith {
            [PSCustomObject]@{ Ace = @() }
        }

        $null = Get-Assessment -State (Get-State)

        Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
                $ProtocolEvidence -eq 'evidence' -and
                @($DistinguishedName).Count -eq 1 -and $DistinguishedName[0] -eq 'DC=contoso,DC=com'
            }
    }

    It 'is readable with no broad entry when only the narrow grants exist' {
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith {
            [PSCustomObject]@{
                Ace = @((Get-AceFixture), (Get-AceFixture -Sid 'S-1-5-21-1-2-3-526'))
            }
        }

        $result = Get-Assessment -State (Get-State)

        $result.Readable | Should -Be $true
        @($result.Broad).Count | Should -Be 0
    }

    It 'returns the broad entries' {
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith {
            [PSCustomObject]@{ Ace = @(Get-AceFixture -Mask 0x10000000 -ObjectType '') }
        }

        $result = Get-Assessment -State (Get-State)

        $result.Readable | Should -Be $true
        @($result.Broad).Count | Should -Be 1
    }

    It 'is not readable when the server returned no descriptor' {
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith {
            [PSCustomObject]@{ Ace = $null }
        }

        $result = Get-Assessment -State (Get-State)

        $result.Readable | Should -Be $false
        @($result.Broad).Count | Should -Be 0
    }

    It 'is not readable without protocol evidence, and does not read' {
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith { }

        $result = Get-Assessment -State (Get-State -ProtocolEvidence $null)

        $result.Readable | Should -Be $false
        Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 0 -Exactly
    }

    It 'is not readable without the distinguished name of the domain' {
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith { }

        $result = Get-Assessment -State (Get-State -Dn '')

        $result.Readable | Should -Be $false
        Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 0 -Exactly
    }

    It 'lets a failed read through' {
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith { throw 'bind failed' }

        { Get-Assessment -State (Get-State) } | Should -Throw '*bind failed*'
    }
}
