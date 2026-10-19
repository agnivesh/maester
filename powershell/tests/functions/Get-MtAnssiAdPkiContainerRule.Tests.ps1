BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Rule {
        InModuleScope Maester { @(Get-MtAnssiAdPkiContainerRule) }
    }
}

Describe 'Get-MtAnssiAdPkiContainerRule' {
    It 'lists the rights that let a principal take over a PKI object, in matching order' {
        $rows = Get-Rule

        @($rows | ForEach-Object { '{0}|0x{1:X}|{2}' -f $_.Control, $_.Mask, $_.ObjectType }) |
            Should -Be @(
            'GenericAll|0x10000000|*'
            'GenericAll|0xF01FF|*'
            'WriteDacl|0x40000|*'
            'WriteOwner|0x80000|*'
            'GenericWrite|0x40000000|*'
            'GenericWrite|0x20|'
            'WriteCaCertificate|0x20|bf967932-0de6-11d0-a285-00aa003049e2'
            'CreateChild|0x1|*'
        )
    }

    It 'gives every right level 1, no class limit and no ignored type' {
        foreach ($row in Get-Rule) {
            $row.Level | Should -Be 1
            $null -eq $row.Class | Should -Be $true
            $null -eq $row.IgnoreType | Should -Be $true
            $row.Mask -is [uint32] | Should -Be $true
        }
    }
}
