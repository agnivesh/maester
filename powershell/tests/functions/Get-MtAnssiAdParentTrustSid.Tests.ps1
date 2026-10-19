BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-TrustFixture {
        param(
            [string] $Partner = 'root.local', $Attributes = 0x20,
            [AllowNull()] [string] $Sid = 'S-1-5-21-9-9-9'
        )
        $sidValue = $null
        if ($Sid) { $sidValue = [PSCustomObject]@{ Value = $Sid } }
        [PSCustomObject]@{ TrustPartner = $Partner; TrustAttributes = $Attributes; Sid = $sidValue }
    }

    function Get-ParentSid {
        param([AllowNull()] [object[]] $Trust, [string] $Forest = 'root.local')
        InModuleScope Maester -Parameters @{ Trust = $Trust; Forest = $Forest } {
            param($Trust, $Forest)
            Get-MtAnssiAdParentTrustSid -Trust $Trust -Forest $Forest
        }
    }
}

Describe 'Get-MtAnssiAdParentTrustSid' {
    It 'returns the SID of the trust inside the forest whose partner is the forest root' {
        $trust = @(
            Get-TrustFixture -Partner 'other.local' -Sid 'S-1-5-21-2-2-2'
            Get-TrustFixture
        )

        Get-ParentSid -Trust $trust | Should -BeExactly 'S-1-5-21-9-9-9'
    }

    It 'skips an unusable trust and takes a later usable one' {
        $trust = @(
            Get-TrustFixture -Sid $null
            Get-TrustFixture -Attributes 0
            Get-TrustFixture -Sid 'S-1-5-21-7-7-7'
        )

        Get-ParentSid -Trust $trust | Should -BeExactly 'S-1-5-21-7-7-7'
    }

    It 'returns nothing for a trust that <Name>' -ForEach @(
        @{ Name = 'has no SID'; Attributes = 0x20; Sid = $null; Partner = 'root.local' }
        @{
            Name = 'is not inside the forest'; Attributes = 0x8
            Sid = 'S-1-5-21-9-9-9'; Partner = 'root.local'
        }
        @{
            Name = 'has no flags'; Attributes = $null
            Sid = 'S-1-5-21-9-9-9'; Partner = 'root.local'
        }
        @{
            Name = 'is for another partner'; Attributes = 0x20
            Sid = 'S-1-5-21-9-9-9'; Partner = 'x.local'
        }
    ) {
        $trust = @(Get-TrustFixture -Partner $Partner -Attributes $Attributes -Sid $Sid)

        $null -eq (Get-ParentSid -Trust $trust) | Should -Be $true
    }

    It 'matches the partner without regard to case and the flag among others and as text' {
        $trust = @(Get-TrustFixture -Partner 'ROOT.Local' -Attributes '44')

        Get-ParentSid -Trust $trust | Should -BeExactly 'S-1-5-21-9-9-9'
    }

    It 'returns nothing without trusts' -ForEach @(
        @{ Trust = @() }
        @{ Trust = $null }
    ) {
        $null -eq (Get-ParentSid -Trust $Trust) | Should -Be $true
    }
}
