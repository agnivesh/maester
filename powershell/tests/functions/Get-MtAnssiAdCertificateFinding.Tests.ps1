BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # The first byte of a fixture certificate is its level (0 for no problem), the second its
    # subject letter.
    function Use-Assessment {
        Mock Get-MtAnssiAdCertificateProblem -ModuleName Maester -MockWith {
            $level = $null
            if ($Certificate[0] -gt 0) { $level = [int]$Certificate[0] }
            [PSCustomObject]@{
                Subject  = "CN=$([char]$Certificate[1])"
                NotAfter = [datetime]::new(2030, 1, $Certificate[1] - 64, 0, 0, 0,
                    [System.DateTimeKind]::Utc)
                Key      = 'RSA'
                Problem  = [string[]]@("problem $($Certificate[0])")
                Level    = $level
            }
        }
    }

    function Get-Store {
        param([string] $Dn, [object[]] $Certificate)
        [PSCustomObject]@{ DistinguishedName = $Dn; Name = 'n'; Certificate = $Certificate }
    }

    function Get-Finding {
        param([object[]] $Object)
        InModuleScope Maester -Parameters @{ Object = $Object } {
            param($Object)
            @(Get-MtAnssiAdCertificateFinding -Object $Object)
        }
    }
}

Describe 'Get-MtAnssiAdCertificateFinding' {
    BeforeEach {
        Use-Assessment
    }

    It 'returns one row per certificate with a problem' {
        $objects = @(
            Get-Store -Dn 'CN=NTAuthCertificates' -Certificate (
                @(, [byte[]](3, 65)) + @(, [byte[]](0, 66)))
            Get-Store -Dn 'CN=Empty' -Certificate @()
        )

        $rows = Get-Finding -Object $objects

        $rows.Count | Should -Be 1
        $rows[0].DistinguishedName | Should -BeExactly 'CN=NTAuthCertificates'
        $rows[0].Subject | Should -BeExactly 'CN=A'
        $rows[0].NotAfter.Day | Should -Be 1
        $rows[0].Problem | Should -BeExactly 'problem 3'
        $rows[0].Level | Should -Be 3
    }

    It 'judges each certificate of an object' {
        $null = Get-Finding -Object @(Get-Store -Dn 'CN=AIA' -Certificate (
                @(, [byte[]](1, 65)) + @(, [byte[]](2, 66)) + @(, [byte[]](0, 67))))

        Should -Invoke Get-MtAnssiAdCertificateProblem -ModuleName Maester -Times 3 -Exactly
        Should -Invoke Get-MtAnssiAdCertificateProblem -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { ($Certificate -join ',') -eq '2,66' }
    }

    It 'sorts by level, then object, then subject' {
        $objects = @(
            Get-Store -Dn 'CN=A' -Certificate (@(, [byte[]](3, 65)) + @(, [byte[]](1, 68)))
            Get-Store -Dn 'CN=B' -Certificate (@(, [byte[]](1, 67)) + @(, [byte[]](1, 66)))
            Get-Store -Dn 'CN=C' -Certificate @(, [byte[]](2, 65))
        )

        $rows = Get-Finding -Object $objects

        ($rows | ForEach-Object { "$($_.Level)$($_.DistinguishedName)$($_.Subject)" }) -join ' ' |
            Should -BeExactly '1CN=ACN=D 1CN=BCN=B 1CN=BCN=C 2CN=CCN=A 3CN=ACN=A'
    }

    It 'returns nothing when no certificate has a problem' {
        $rows = Get-Finding -Object @(Get-Store -Dn 'CN=A' -Certificate @(, [byte[]](0, 65)))

        $rows.Count | Should -Be 0
    }

    It 'returns nothing for no object' {
        (Get-Finding -Object @()).Count | Should -Be 0
    }
}
