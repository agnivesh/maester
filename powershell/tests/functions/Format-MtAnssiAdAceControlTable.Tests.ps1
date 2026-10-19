BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-RowFixture {
        param(
            [string] $Object, [string] $Sid, [string] $Control, [int] $Level,
            [bool] $Inherited = $false
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Object,DC=x"; Name = $Object; Sid = $Sid
            Control = $Control; Level = $Level; IsInherited = $Inherited
        }
    }

    function Get-PrincipalFixture {
        param([string] $Sid, [string] $Sam, [string] $Name)
        [PSCustomObject]@{
            Sid = [PSCustomObject]@{ Value = $Sid }; SamAccountName = $Sam; Name = $Name
        }
    }

    function Get-Table {
        param([object[]] $Row, [AllowNull()] [object[]] $Principal)
        InModuleScope Maester -Parameters @{ Row = $Row; Principal = $Principal } {
            param($Row, $Principal)
            Format-MtAnssiAdAceControlTable -Row $Row -Principal $Principal
        }
    }

    function Get-Line {
        param([string] $Table)
        @(($Table -replace '\\', '') -split "`n" | Select-Object -Skip 2 | Where-Object { $_ })
    }
}

Describe 'Format-MtAnssiAdAceControlTable' {
    It 'names trustees by account name, name, well-known name or SID' {
        $rows = @(
            Get-RowFixture -Object 'o' -Sid 'S-1-5-21-1-2-3-1105' -Control 'WriteDacl' -Level 1
            Get-RowFixture -Object 'o' -Sid 'S-1-5-21-1-2-3-1106' -Control 'WriteDacl' -Level 1
            Get-RowFixture -Object 'o' -Sid 'S-1-1-0' -Control 'WriteDacl' -Level 1
            Get-RowFixture -Object 'o' -Sid 'S-1-5-11' -Control 'WriteDacl' -Level 1
            Get-RowFixture -Object 'o' -Sid 'S-1-5-7' -Control 'WriteDacl' -Level 1
            Get-RowFixture -Object 'o' -Sid 'S-1-5-21-9-9-9-1' -Control 'WriteDacl' -Level 1
        )
        $principal = @(
            Get-PrincipalFixture -Sid 'S-1-5-21-1-2-3-1105' -Sam 'k_alice' -Name 'Alice'
            Get-PrincipalFixture -Sid 'S-1-5-21-1-2-3-1106' -Sam '' -Name 'bob'
            Get-PrincipalFixture -Sid 'S-1-5-21-1-2-3-1107' -Sam 'unused' -Name 'unused'
        )

        $lines = Get-Line -Table (Get-Table -Row $rows -Principal $principal)

        @($lines | ForEach-Object { ($_ -split '\|')[3].Trim() }) -join ';' | Should -BeExactly (
            'Anonymous Logon;Authenticated Users;bob;Everyone;k_alice;S-1-5-21-9-9-9-1')
    }

    It 'sorts by level, then object, then trustee, and shows severity and inheritance' {
        $rows = @(
            Get-RowFixture -Object 'a' -Sid 'S-1-1-0' -Control 'WriteSpn' -Level 2
            Get-RowFixture -Object 'b' -Sid 'S-1-5-11' -Control 'WriteDacl' -Level 1 `
                -Inherited $true
            Get-RowFixture -Object 'a' -Sid 'S-1-5-11' -Control 'WriteOwner' -Level 1
            Get-RowFixture -Object 'a' -Sid 'S-1-1-0' -Control 'GenericAll' -Level 1
        )

        $lines = Get-Line -Table (Get-Table -Row $rows -Principal $null)

        $lines -join "`n" | Should -BeExactly ((@(
                    '| x | a | Authenticated Users | WriteOwner | Critical | No |'
                    '| x | a | Everyone | GenericAll | Critical | No |'
                    '| x | b | Authenticated Users | WriteDacl | Critical | Yes |'
                    '| x | a | Everyone | WriteSpn | High | No |'
                ) -join "`n"))
    }

    It 'returns a table with the six columns' {
        $row = Get-RowFixture -Object 'a' -Sid 'S-1-1-0' -Control 'WriteDacl' -Level 1

        $table = Get-Table -Row @($row) -Principal @()

        ($table -split "`n")[0] |
            Should -BeExactly '| Domain | Object | Trustee | Right | Severity | Inherited |'
    }

    It 'adds the Exchange note after the table when a trustee is an Exchange group' {
        $rows = @(
            Get-RowFixture -Object 'o' -Sid 'S-1-5-21-1-2-3-1105' -Control 'WriteDacl' -Level 1
            Get-RowFixture -Object 'o' -Sid 'S-1-5-21-1-2-3-1106' -Control 'GenericAll' -Level 1
        )
        $principal = @(
            Get-PrincipalFixture -Sid 'S-1-5-21-1-2-3-1105' -Sam 'Exchange Servers' -Name 'x'
            Get-PrincipalFixture -Sid 'S-1-5-21-1-2-3-1106' -Sam 'alice' -Name 'Alice'
        )

        $table = Get-Table -Row $rows -Principal $principal

        $parts = $table -split "`n`n"
        $parts.Count | Should -Be 2
        $parts[0] | Should -Match '^\| Domain \| Object \|'
        $parts[0] | Should -Not -Match 'PrivExchange'
        $parts[1] | Should -Match '^Exchange groups among the trustees: Exchange Servers'
        $table | Should -Not -Match "`n`n`n"
    }

    It 'adds no note when no trustee is an Exchange group' {
        $row = Get-RowFixture -Object 'a' -Sid 'S-1-5-21-1-2-3-1105' -Control 'WriteDacl' -Level 1
        $principal = @(
            Get-PrincipalFixture -Sid 'S-1-5-21-1-2-3-1105' -Sam 'alice' -Name 'Alice'
        )

        $table = Get-Table -Row @($row) -Principal $principal

        $table | Should -Not -Match 'PrivExchange'
        $table | Should -Not -Match "`n`n"
    }

    It 'shows the domain of each object, read from its distinguished name' {
        $rows = @(
            Get-RowFixture -Object 'a' -Sid 'S-1-1-0' -Control 'WriteDacl' -Level 1
            Get-RowFixture -Object 'b' -Sid 'S-1-1-0' -Control 'WriteDacl' -Level 1
        )
        $rows[1].DistinguishedName = 'CN=b,DC=child,DC=x'

        $lines = Get-Line -Table (Get-Table -Row $rows -Principal $null)

        $domains = @($lines | ForEach-Object { ($_ -split '\|')[1].Trim() }) -join ';'
        $domains | Should -BeExactly 'x;child.x'
    }

    It 'shows the object without the domain suffix that the Domain column already gives' {
        $row = Get-RowFixture -Object 'a' -Sid 'S-1-1-0' -Control 'WriteDacl' -Level 1
        $row.Name = 'CN=Users,DC=x'

        $lines = @(Get-Line -Table (Get-Table -Row @($row) -Principal $null))

        $lines[0] | Should -BeLike '| x | CN=Users | Everyone |*'
    }
}
