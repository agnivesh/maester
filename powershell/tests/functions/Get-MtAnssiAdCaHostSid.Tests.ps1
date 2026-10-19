BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-ServiceFixture {
        param([string] $Name, [AllowNull()] $HostName)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=Enrollment Services"
            Name              = $Name
            Attribute         = [ordered]@{ dNSHostName = $HostName }
        }
    }

    function Get-ComputerFixture {
        param([string] $HostName, [AllowNull()] [string] $Sid)
        $sidValue = $null
        if ($Sid) { $sidValue = [PSCustomObject]@{ Value = $Sid } }
        [PSCustomObject]@{ DnsHostName = $HostName; Sid = $sidValue }
    }

    function Get-HostSid {
        param([object[]] $Service, [AllowNull()] [object[]] $Computer)
        InModuleScope Maester -Parameters @{ Service = $Service; Computer = $Computer } {
            param($Service, $Computer)
            @(Get-MtAnssiAdCaHostSid -EnrollmentService $Service -Computer $Computer)
        }
    }
}

Describe 'Get-MtAnssiAdCaHostSid' {
    It 'returns the SID of the computer that hosts each CA' {
        $service = @(
            Get-ServiceFixture -Name 'CA1' -HostName 'ca1.contoso.com'
            Get-ServiceFixture -Name 'CA2' -HostName 'ca2.contoso.com'
        )
        $computer = @(
            Get-ComputerFixture -HostName 'ca1.contoso.com' -Sid 'S-1-5-21-1-2-3-1106'
            Get-ComputerFixture -HostName 'other.contoso.com' -Sid 'S-1-5-21-1-2-3-1107'
            Get-ComputerFixture -HostName 'ca2.contoso.com' -Sid 'S-1-5-21-1-2-3-1108'
        )

        Get-HostSid -Service $service -Computer $computer |
            Should -Be @('S-1-5-21-1-2-3-1106', 'S-1-5-21-1-2-3-1108')
    }

    It 'matches the host name without regard to case' {
        $service = @(Get-ServiceFixture -Name 'CA1' -HostName 'CA1.Contoso.COM')
        $computer = @(Get-ComputerFixture -HostName 'ca1.contoso.com' -Sid 'S-1-5-21-1-2-3-1106')

        Get-HostSid -Service $service -Computer $computer | Should -Be @('S-1-5-21-1-2-3-1106')
    }

    It 'returns the SID once when two CAs run on the same computer' {
        $service = @(
            Get-ServiceFixture -Name 'CA1' -HostName 'ca1.contoso.com'
            Get-ServiceFixture -Name 'CA2' -HostName 'ca1.contoso.com'
        )
        $computer = @(Get-ComputerFixture -HostName 'ca1.contoso.com' -Sid 'S-1-5-21-1-2-3-1106')

        @(Get-HostSid -Service $service -Computer $computer).Count | Should -Be 1
    }

    It 'returns nothing for a host that is not among the computers' {
        $service = @(Get-ServiceFixture -Name 'CA1' -HostName 'ca1.otherdomain.com')
        $computer = @(Get-ComputerFixture -HostName 'ca1.contoso.com' -Sid 'S-1-5-21-1-2-3-1106')

        @(Get-HostSid -Service $service -Computer $computer).Count | Should -Be 0
    }

    It 'ignores a CA without a host name and a computer without a SID' -ForEach @(
        @{ HostName = $null; Sid = 'S-1-5-21-1-2-3-1106' }
        @{ HostName = ''; Sid = 'S-1-5-21-1-2-3-1106' }
        @{ HostName = 'ca1.contoso.com'; Sid = $null }
    ) {
        $service = @(Get-ServiceFixture -Name 'CA1' -HostName $HostName)
        $computer = @(
            Get-ComputerFixture -HostName '' -Sid 'S-1-5-21-1-2-3-1999'
            Get-ComputerFixture -HostName 'ca1.contoso.com' -Sid $Sid
        )

        @(Get-HostSid -Service $service -Computer $computer).Count | Should -Be 0
    }

    It 'accepts no computers and no CAs' -ForEach @(
        @{ Service = @(); Computer = @() }
        @{ Service = @(); Computer = $null }
    ) {
        @(Get-HostSid -Service $Service -Computer $Computer).Count | Should -Be 0
    }
}
