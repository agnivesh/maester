BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Cycle {
        param([hashtable] $Forward)
        InModuleScope Maester -Parameters @{ Forward = $Forward } {
            param($Forward)
            $reverse = @{}
            foreach ($node in @($Forward.Keys)) {
                foreach ($target in $Forward[$node]) {
                    if (-not $reverse.ContainsKey($target)) { $reverse[$target] = @() }
                    $reverse[$target] += $node
                }
            }
            $order = Get-MtAnssiAdDepthFirstOrder -Node @($Forward.Keys) -Edge $Forward
            @(Get-MtAnssiAdStrongComponent -Order $order -Forward $Forward -Reverse $reverse |
                    ForEach-Object { (@($_) | Sort-Object) -join ',' } | Sort-Object)
        }
    }
}

Describe 'Get-MtAnssiAdStrongComponent' {
    It 'returns the nodes of a cycle and leaves out a node that only leads into it' {
        $cycles = Get-Cycle -Forward @{ a = @('b'); b = @('c'); c = @('a'); x = @('a') }

        $cycles | Should -Be @('a,b,c')
    }

    It 'returns each separate cycle' {
        $cycles = Get-Cycle -Forward @{ a = @('b'); b = @('a'); c = @('d'); d = @('c'); e = @() }

        $cycles | Should -Be @('a,b', 'c,d')
    }

    It 'returns a node that points to itself' {
        Get-Cycle -Forward @{ a = @('a'); b = @() } | Should -Be @('a')
    }

    It 'returns nothing for a graph without a cycle' {
        (Get-Cycle -Forward @{ a = @('b'); b = @('c'); c = @() }).Count | Should -Be 0
    }

    It 'treats names that differ only by case as one node' {
        $result = InModuleScope Maester {
            @(Get-MtAnssiAdStrongComponent -Order @('a', 'A') -Forward @{ a = @('a') } `
                    -Reverse @{ a = @('a') })
        }

        $result.Count | Should -Be 1
        @($result[0]).Count | Should -Be 1
    }

    It 'returns nothing for an empty graph' {
        $result = InModuleScope Maester {
            @(Get-MtAnssiAdStrongComponent -Order @() -Forward @{} -Reverse @{})
        }

        $result.Count | Should -Be 0
    }
}
