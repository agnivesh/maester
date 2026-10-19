function Get-MtLdapComputer {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection] $Connection,

        [string] $SearchBase
    )

    function ConvertFrom-LdapInteger {
        param([object] $Value)

        $number = 0
        if ([int]::TryParse([string]$Value, [ref]$number)) { return $number }
        return $null
    }

    function ConvertFrom-ResourceDelegation {
        param([object] $Value)

        if ($null -eq $Value) { return $null }
        $sids = @()
        try { $sids = @(Get-MtLdapSecurityDescriptorAllowSid -Descriptor ([byte[]]$Value)) }
        catch { Write-Verbose "Could not read a resource-based delegation descriptor: $($_.Exception.Message)" }
        return , [string[]]$sids
    }

    if ([string]::IsNullOrWhiteSpace($SearchBase)) { $SearchBase = (Get-MtLdapRootDse -Connection $Connection).DefaultNamingContext }
    $attributes = @('distinguishedName', 'name', 'sAMAccountName', 'userAccountControl', 'operatingSystem', 'operatingSystemVersion', 'dNSHostName', 'whenCreated', 'whenChanged', 'lastLogonTimestamp', 'pwdLastSet', 'servicePrincipalName', 'primaryGroupID', 'objectSid', 'isCriticalSystemObject', 'managedBy', 'sIDHistory', 'msDS-SupportedEncryptionTypes', 'msDS-KrbTgtLink', 'objectClass', 'msDS-NeverRevealGroup', 'msDS-RevealOnDemandGroup', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity')
    $entries = @(Invoke-MtLdapSearch -Connection $Connection -SearchBase $SearchBase -Scope Subtree -Filter '(objectClass=computer)' -Attributes $attributes)
    return @($entries | ForEach-Object {
        $uac = if ($null -ne $_.userAccountControl) { ConvertFrom-MtLdapUserAccountControl -UserAccountControl ([int]$_.userAccountControl) } else { $null }
        [PSCustomObject]@{
            DistinguishedName = [string]$_.DistinguishedName; Name = [string]$_.name; SamAccountName = [string]$_.sAMAccountName
            Enabled = if ($null -ne $uac) { -not $uac.AccountDisabled } else { $null }; OperatingSystem = [string]$_.operatingSystem; OperatingSystemVersion = [string]$_.operatingSystemVersion
            DnsHostName = [string]$_.dNSHostName; Created = $_.whenCreated; Modified = $_.whenChanged; LastLogonDate = $_.lastLogonTimestamp
            PasswordLastSet = $_.pwdLastSet; PasswordExpired = if ($null -ne $uac) { $uac.PasswordExpired } else { $null }; PasswordNeverExpires = if ($null -ne $uac) { $uac.DontExpirePassword } else { $null }
            PasswordNotRequired = if ($null -ne $uac) { $uac.PasswordNotRequired } else { $null }; TrustedForDelegation = if ($null -ne $uac) { $uac.TrustedForDelegation } else { $null }
            TrustedToAuthForDelegation = if ($null -ne $uac) { $uac.TrustedToAuthForDelegation } else { $null }; ServicePrincipalName = [string[]]@($_.servicePrincipalName | Where-Object { $null -ne $_ })
            PrimaryGroupId = $_.primaryGroupID; Sid = $_.objectSid; UserAccountControl = [int]$_.userAccountControl
            IsCriticalSystemObject = if ($null -ne $_.isCriticalSystemObject) { [bool]$_.isCriticalSystemObject } else { $null }; ManagedBy = [string]$_.managedBy; SidHistory = @($_.sIDHistory | Where-Object { $null -ne $_ })
            SupportedEncryptionTypes = ConvertFrom-LdapInteger -Value $_.'msDS-SupportedEncryptionTypes'
            KrbTgtLink = if ($null -ne $_.'msDS-KrbTgtLink') { [string]$_.'msDS-KrbTgtLink' } else { $null }
            ObjectClass = [string[]]@($_.objectClass | Where-Object { $null -ne $_ })
            NeverRevealGroup = [string[]]@($_.'msDS-NeverRevealGroup' | Where-Object { $null -ne $_ })
            RevealOnDemandGroup = [string[]]@($_.'msDS-RevealOnDemandGroup' | Where-Object { $null -ne $_ })
            AllowedToDelegateTo = [string[]]@($_.'msDS-AllowedToDelegateTo' | Where-Object { $null -ne $_ })
            AllowedToActOnBehalfOfOtherIdentity = ConvertFrom-ResourceDelegation -Value $_.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        }
    })
}
