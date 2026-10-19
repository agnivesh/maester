BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Weakness {
        param([AllowNull()] [object] $MinLength, [AllowNull()] [object] $MaxAge)
        InModuleScope Maester -Parameters @{ MinLength = $MinLength; MaxAge = $MaxAge } {
            param($MinLength, $MaxAge)
            @(Get-MtAnssiAdPasswordPolicyWeakness -MinLength $MinLength -MaxAge $MaxAge)
        }
    }
}

Describe 'Get-MtAnssiAdPasswordPolicyWeakness' {
    It 'finds <Expected> for length <MinLength> and <Days> days' -ForEach @(
        @{ MinLength = 8; Days = 90; Expected = '' }
        @{ MinLength = '14'; Days = 1095; Expected = '' }
        @{ MinLength = 7; Days = 90; Expected = 'minimum length 7' }
        @{ MinLength = $null; Days = 90; Expected = 'minimum length 0' }
        @{ MinLength = 8; Days = 1096; Expected = 'maximum age 1096 days' }
        @{ MinLength = 8; Days = 0; Expected = 'passwords never expire' }
        @{ MinLength = 6; Days = -1; Expected = 'minimum length 6|passwords never expire' }
    ) {
        $maxAge = $null
        if ($Days -ge 0) { $maxAge = [timespan]::FromDays($Days) }

        $result = Get-Weakness -MinLength $MinLength -MaxAge $maxAge

        ($result -join '|') | Should -BeExactly $Expected
    }
}
