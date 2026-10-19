BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Order {
        param([string[]] $Node, [hashtable] $Edge)
        InModuleScope Maester -Parameters @{ Node = $Node; Edge = $Edge } {
            param($Node, $Edge)
            @(Get-MtAnssiAdDepthFirstOrder -Node $Node -Edge $Edge)
        }
    }
}

Describe 'Get-MtAnssiAdDepthFirstOrder' {
    It 'returns every node once, each after the nodes it reaches' {
        $edge = @{ a = @('b'); b = @('c'); c = @('a', 'd'); d = @() }
        $order = Get-Order -Node 'a', 'd' -Edge $edge

        $order -join ',' | Should -BeExactly 'd,c,b,a'
    }

    It 'starts a new walk from each node not reached yet' {
        $order = Get-Order -Node 'x', 'a' -Edge @{ a = @('b') }

        $order -join ',' | Should -BeExactly 'x,b,a'
    }

    It 'treats names that differ only by case as one node' {
        $order = Get-Order -Node 'a', 'A' -Edge @{ a = @('A') }

        $order -join ',' | Should -BeExactly 'a'
    }

    It 'walks a chain of 5000 nodes without recursion' {
        $edge = @{}
        for ($i = 0; $i -lt 5000; $i++) { $edge["n$i"] = @("n$($i + 1)") }

        $order = Get-Order -Node 'n0' -Edge $edge

        $order.Count | Should -Be 5001
        $order[0] | Should -BeExactly 'n5000'
        $order[-1] | Should -BeExactly 'n0'
    }

    It 'returns nothing for no node' {
        (Get-Order -Node @() -Edge @{}).Count | Should -Be 0
    }
}
