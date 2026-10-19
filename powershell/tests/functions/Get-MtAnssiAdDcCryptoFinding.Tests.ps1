BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-ControllerFixture {
        param(
            [string] $Name = 'DC1',
            [AllowNull()] [object] $Types = 24,
            [int] $Uac = 532480,
            [string] $Type = 'Writable'
        )
        [PSCustomObject]@{
            Type     = $Type
            Computer = [PSCustomObject]@{
                Name                     = $Name
                DistinguishedName        = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
                SupportedEncryptionTypes = $Types
                UserAccountControl       = $Uac
            }
        }
    }

    function Get-Finding {
        param([AllowNull()] [object[]] $Controller)
        InModuleScope Maester -Parameters @{ Controller = $Controller } {
            param($Controller)
            Get-MtAnssiAdDcCryptoFinding -Controller $Controller
        }
    }
}

Describe 'Get-MtAnssiAdDcCryptoFinding' {
    Context 'controllers without a finding' {
        It 'returns nothing for AES only (<Types>)' -ForEach @(
            @{ Types = 24 }
            @{ Types = 8 }
            @{ Types = 16 }
            @{ Types = 56 }
        ) {
            @(Get-Finding -Controller @(Get-ControllerFixture -Types $Types)).Count | Should -Be 0
        }

        It 'returns nothing for null or empty input' {
            @(Get-Finding -Controller $null).Count | Should -Be 0
            @(Get-Finding -Controller @()).Count | Should -Be 0
        }
    }

    Context 'grades' {
        It 'grades RC4 with AES as 4' {
            $result = @(Get-Finding -Controller @(Get-ControllerFixture -Types 28))

            $result.Count | Should -Be 1
            $result[0].Grade | Should -Be 4
            $result[0].Condition | Should -BeExactly 'RC4 enabled'
        }

        It 'grades a value without AES as 3 and adds RC4 as 4 for RC4 only' {
            $result = @(Get-Finding -Controller @(Get-ControllerFixture -Types 4))

            $result[0].Grade | Should -Be 3
            $result[0].Condition | Should -BeExactly 'No AES128 or AES256, RC4 enabled'
        }

        It 'grades a controller without a value as 3 and not as RC4' {
            $result = @(Get-Finding -Controller @(Get-ControllerFixture -Types $null))

            $result[0].Grade | Should -Be 3
            $result[0].Condition | Should -BeExactly 'No AES128 or AES256'
        }

        It 'treats 0 like no value' {
            $result = @(Get-Finding -Controller @(Get-ControllerFixture -Types 0))

            $result[0].Grade | Should -Be 3
        }

        It 'grades DES as 2 for DES-CBC-CRC and DES-CBC-MD5' -ForEach @(
            @{ Types = 25 }
            @{ Types = 26 }
        ) {
            $result = @(Get-Finding -Controller @(Get-ControllerFixture -Types $Types))

            $result[0].Grade | Should -Be 2
            $result[0].Condition | Should -BeExactly 'DES enabled'
        }

        It 'grades DES with RC4 and no AES as 2 and lists every condition' {
            $result = @(Get-Finding -Controller @(Get-ControllerFixture -Types 7))

            $result[0].Grade | Should -Be 2
            $result[0].Condition |
                Should -BeExactly 'DES enabled, No AES128 or AES256, RC4 enabled'
        }

        It 'grades a controller set to use DES keys only as 2' {
            $uac = 532480 -bor 0x200000
            $result = @(Get-Finding -Controller @(Get-ControllerFixture -Types 24 -Uac $uac))

            $result[0].Grade | Should -Be 2
            $result[0].Condition | Should -BeExactly 'DES enabled'
        }

        It 'reads a value given as text' {
            $result = @(Get-Finding -Controller @(Get-ControllerFixture -Types '28'))

            $result[0].Grade | Should -Be 4
        }
    }

    Context 'result' {
        It 'sorts by grade, then by name' {
            $result = @(Get-Finding -Controller @(
                    (Get-ControllerFixture -Name 'A-RC4' -Types 28)
                    (Get-ControllerFixture -Name 'Z-DES' -Types 27)
                    (Get-ControllerFixture -Name 'B-NOAES' -Types 4)
                    (Get-ControllerFixture -Name 'A-DES' -Types 27)
                ))

            $names = $result | ForEach-Object { $_.Name }
            $names -join ',' | Should -Be 'A-DES,Z-DES,B-NOAES,A-RC4'
        }

        It 'returns the name, DN, type and value of the controller' {
            $result = @(Get-Finding -Controller @(
                    Get-ControllerFixture -Name 'RO1' -Types 28 -Type 'ReadOnly'))

            $result[0].Name | Should -Be 'RO1'
            $result[0].DistinguishedName |
                Should -Be 'CN=RO1,OU=Domain Controllers,DC=contoso,DC=com'
            $result[0].Type | Should -Be 'ReadOnly'
            $result[0].SupportedEncryptionTypes | Should -Be 28
        }

        It 'leaves out the controllers that comply' {
            $result = @(Get-Finding -Controller @(
                    (Get-ControllerFixture -Name 'good' -Types 24)
                    (Get-ControllerFixture -Name 'bad' -Types 28)
                ))

            $result.Count | Should -Be 1
            $result[0].Name | Should -Be 'bad'
        }
    }
}
