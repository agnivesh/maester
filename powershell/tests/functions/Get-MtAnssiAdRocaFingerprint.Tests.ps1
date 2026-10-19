BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:primes = @(3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167)

    # Builds a 2048-bit modulus with the given remainders (1 for the primes not named) by the
    # Chinese remainder theorem, then returns it most significant byte first.
    function Get-Modulus {
        param([hashtable] $Remainder = @{})
        $product = [System.Numerics.BigInteger]::One
        foreach ($prime in $script:primes) { $product *= $prime }
        $value = [System.Numerics.BigInteger]::Zero
        foreach ($prime in $script:primes) {
            $wanted = 1
            if ($Remainder.ContainsKey($prime)) { $wanted = $Remainder[$prime] }
            $rest = $product / $prime
            $inverse = [System.Numerics.BigInteger]::ModPow($rest % $prime, $prime - 2, $prime)
            $value += $wanted * $rest * $inverse
        }
        $value = $value % $product + $product * [System.Numerics.BigInteger]::Pow(2, 1830)
        $bytes = $value.ToByteArray()
        [array]::Reverse($bytes)
        while ($bytes[0] -eq 0) { $bytes = $bytes[1..($bytes.Length - 1)] }
        [byte[]]$bytes
    }

    function Test-Modulus {
        param([byte[]] $Modulus)
        InModuleScope Maester -Parameters @{ Modulus = $Modulus } {
            param($Modulus)
            Get-MtAnssiAdRocaFingerprint -Modulus $Modulus
        }
    }
}

Describe 'Get-MtAnssiAdRocaFingerprint' {
    It 'matches a modulus whose remainders all lie in the groups of 65537' {
        Test-Modulus -Modulus (Get-Modulus) | Should -Be $true
    }

    It 'matches remainders other than 1 that lie in the group: <Name>' -ForEach @(
        @{ Name = '65537 mod 11 is 10'; Remainder = @{ 11 = 10 } }
        @{ Name = '65537 squared mod 7 is 2'; Remainder = @{ 7 = 2 } }
        @{ Name = 'the last prime'; Remainder = @{ 167 = 73 } }
    ) {
        Test-Modulus -Modulus (Get-Modulus -Remainder $Remainder) | Should -Be $true
    }

    It 'does not match when only the remainder by <Prime> is <Value>, outside the group' -ForEach @(
        @{ Prime = 3; Value = 0 }
        @{ Prime = 11; Value = 2 }
        @{ Prime = 167; Value = 0 }
        @{ Prime = 13; Value = 2 }
    ) {
        Test-Modulus -Modulus (Get-Modulus -Remainder @{ $Prime = $Value }) | Should -Be $false
    }

    It 'does not match an ordinary modulus' {
        Test-Modulus -Modulus ([byte[]](@(0xC0) * 256)) | Should -Be $false
    }

    It 'does not match an empty modulus' {
        Test-Modulus -Modulus ([byte[]]@()) | Should -Be $false
    }
}
