BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Group {
        param([string] $Name, [string[]] $Parent = @())
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=x"
            Name              = $Name
            MemberOf          = [string[]]@($Parent | ForEach-Object { "CN=$_,DC=x" })
        }
    }

    function Get-Loop {
        param([object[]] $Group)
        InModuleScope Maester -Parameters @{ Group = $Group } {
            param($Group)
            @(Get-MtAnssiAdGroupLoop -Group $Group)
        }
    }

    function Get-LoopName {
        param([object[]] $Loop)
        @($Loop | ForEach-Object { @($_.Group | ForEach-Object { $_.Name }) -join ',' })
    }
}

Describe 'Get-MtAnssiAdGroupLoop' {
    It 'finds two groups that are members of each other, sorted by name' {
        $loops = Get-Loop -Group @(
            Get-Group -Name 'Ops' -Parent 'Admins'
            Get-Group -Name 'Admins' -Parent 'Ops'
        )

        Get-LoopName -Loop $loops | Should -Be @('Admins,Ops')
    }

    It 'finds a longer loop and leaves out a group that only leads into it' {
        $loops = Get-Loop -Group @(
            Get-Group -Name 'A' -Parent 'B'
            Get-Group -Name 'B' -Parent 'C'
            Get-Group -Name 'C' -Parent 'A'
            Get-Group -Name 'Outside' -Parent 'A'
        )

        Get-LoopName -Loop $loops | Should -Be @('A,B,C')
    }

    It 'finds a group that is a member of itself' {
        Get-LoopName -Loop (Get-Loop -Group @(Get-Group -Name 'Self' -Parent 'Self')) |
            Should -Be @('Self')
    }

    It 'returns the loops sorted by the name of their first group' {
        $loops = Get-Loop -Group @(
            Get-Group -Name 'Y' -Parent 'Z'; Get-Group -Name 'Z' -Parent 'Y'
            Get-Group -Name 'B' -Parent 'A'; Get-Group -Name 'A' -Parent 'B'
        )

        Get-LoopName -Loop $loops | Should -Be @('A,B', 'Y,Z')
    }

    It 'follows a parent name written in another case' {
        $loops = Get-Loop -Group @(
            Get-Group -Name 'A' -Parent 'b'
            Get-Group -Name 'B' -Parent 'A'
        )

        Get-LoopName -Loop $loops | Should -Be @('A,B')
    }

    It 'finds no loop in nesting without a cycle, or through a parent that is not collected' {
        $loops = Get-Loop -Group @(
            Get-Group -Name 'A' -Parent 'B', 'Elsewhere'
            Get-Group -Name 'B' -Parent 'C'
            Get-Group -Name 'C'
        )

        $loops.Count | Should -Be 0
    }

    It 'returns nothing for no group' {
        (Get-Loop -Group @()).Count | Should -Be 0
    }
}
