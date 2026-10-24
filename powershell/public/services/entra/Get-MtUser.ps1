function Get-MtUser {
    <#
    .SYNOPSIS
    Get a list of users from the tenant

    .DESCRIPTION
    This function retrieves a list of users from the tenant.
    You can specify the number of users to retrieve, the type of users (Member, Guest, Admin) and the role the users are member of.

    .PARAMETER Count
    The number of users to retrieve. Default is 1.

    .PARAMETER UserType
    The type of users to retrieve. Default is Member. Valid values are Member, Guest, Admin, EmergencyAccess and BreakGlass.
    EmergencyAccess and BreakGlass return the accounts and group members listed under EmergencyAccessAccounts in maester-config.json, and nothing when none are configured.

    .PARAMETER MemberOfRole
    The role the users are member of. Default is None. Valid values are Global Administrator, Application Administrator, Authentication Administrator, Billing Administrator, Cloud Application Administrator, Conditional Access Administrator, Exchange Administrator, Helpdesk Administrator, Password Administrator, Privileged Authentication Administrator, Privileged Role Administrator, Security Administrator, SharePoint Administrator, User Administrator.

    .EXAMPLE
    Get-MtUser -Count 5 -UserType Member
    # Get 5 Member users from the tenant.

    .LINK
    https://maester.dev/docs/commands/Get-MtUser
    #>
    [OutputType([System.Collections.ArrayList])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$Count = 1,

        [Parameter()]
        [ValidateSet("Member", "Guest", "Admin", "EmergencyAccess", "BreakGlass")]
        [string]$UserType = "Member",

        [Parameter()]
        [ValidateSet("Global Administrator", "Application Administrator", "Authentication Administrator", "Billing Administrator", "Cloud Application Administrator", "Conditional Access Administrator", "Exchange Administrator", "Helpdesk Administrator", "Password Administrator", "Privileged Authentication Administrator", "Privileged Role Administrator", "Security Administrator", "SharePoint Administrator", "User Administrator")]
        [string]$MemberOfRole
    )

    begin {

        $Users = New-Object -TypeName 'System.Collections.ArrayList'

        # Default roles that will be queried for UserType "Admin"
        $AdminRoles = @(
            "Global Administrator",
            "Application Administrator",
            "Authentication Administrator",
            "Billing Administrator",
            "Cloud Application Administrator",
            "Conditional Access Administrator",
            "Exchange Administrator",
            "Helpdesk Administrator",
            "Password Administrator",
            "Privileged Authentication Administrator",
            "Privileged Role Administrator",
            "Security Administrator",
            "SharePoint Administrator",
            "User Administrator"
        )
    }

    process {

        Write-Verbose "Getting $Count $UserType users from the tenant."

        if ( $UserType -eq "Admin" ) {
            $UserType = "Member"
            if ( $MemberOfRole ) {
                Write-Verbose "Getting $UserType users that are member of $MemberOfRole."
                $AdminRoles = $MemberOfRole
            } else {
                Write-Verbose "Getting $UserType users that are member of any admin role."
            }
            $EntraIDRoles = Invoke-MtGraphRequest -ApiVersion beta 'directoryRoles' | Where-Object { $_.displayName -in $AdminRoles } | Select-Object id, displayName
            foreach ( $EntraIDRole in $EntraIDRoles ) {
                $TmpUsers = Invoke-MtGraphRequest -RelativeUri "directoryRoles/$($EntraIDRole.id)/members" -Select id, userPrincipalName, userType -OutputType Hashtable
                if ( $TmpUsers.ContainsKey('userType') ) {
                    Write-Verbose "Setting userType to Admin for $(($TmpUsers | Measure-Object).count) users that are member of $($EntraIDRole.displayName)."
                    $TmpUsers | ForEach-Object {
                        $_.userType = "Admin"
                        $Users.Add($_) | Out-Null
                        if ($Users.Count -ge $Count) {
                            Write-Verbose "Found $Count $UserType users."
                            break
                        }
                    }
                }
            }
        } elseif ( $UserType -in @("BreakGlass", "EmergencyAccess") ) {
            Write-Verbose "Getting $UserType users from the tenant."
            # Only the accounts in maester-config.json count. Errors are not caught here: a configured
            # account that cannot be read must stop the check instead of being left out.
            $ConfiguredAccounts = @(Get-MtEmergencyAccessAccount)
            if ( $ConfiguredAccounts.Count -gt 0 ) {
                Write-Verbose "Using $($ConfiguredAccounts.Count) emergency access account(s) from the Maester configuration."
                foreach ( $ConfiguredAccount in $ConfiguredAccounts ) {
                    if ( $ConfiguredAccount.Type -eq 'group' ) {
                        $RawResponse = Invoke-MtGraphRequest -RelativeUri "groups/$($ConfiguredAccount.ObjectId)/members" -Select id, userPrincipalName, userType -OutputType Hashtable -DisablePaging -ErrorAction Stop
                        $TmpUsers = if ($null -ne $RawResponse -and $RawResponse.ContainsKey('value')) { @($RawResponse['value']) } else { @() }
                    } else {
                        $TmpUsers = @(Invoke-MtGraphRequest -RelativeUri "users/$($ConfiguredAccount.ObjectId)" -Select id, userPrincipalName, userType -OutputType Hashtable -ErrorAction Stop)
                    }
                    foreach ( $TmpUser in $TmpUsers ) {
                        $TmpUser.userType = "EmergencyAccess"
                        $Users.Add($TmpUser) | Out-Null
                    }
                }
                if ( $Users.Count -gt $Count ) {
                    $Users.RemoveRange($Count, $Users.Count - $Count)
                }
                return $Users
            }

            Write-Verbose "No emergency access accounts are configured in the Maester configuration."
        } else {
            if ( $UserType -eq "Member" ) {
                $queryFilter = "userType eq 'Member'"
            } elseif ( $UserType -eq "Guest" ) {
                $queryFilter = "userType eq 'Guest'"
            } else {
                Write-Warning "UserType $($UserType) cannot be processed! Aborting!"
                throw "User can not be queried, invalid UserType: $($UserType)"
            }

            if ($Count -gt 999) {
                Write-Verbose "The maximum number of users that can be retrieved on one page is 999. Using paging to retrieve $Count users."

                $TmpUsers = Invoke-MtGraphRequest -ApiVersion beta -RelativeUri 'users' -Select id, userPrincipalName, userType -Filter $queryFilter -QueryParameters @{'$top' = 999 } -OutputType Hashtable
                $Count = if ( $TmpUsers.Count -lt $Count ) { $TmpUsers.Count } else { $Count }

                Write-Verbose "Retrieved $($TmpUsers.Count) users"
                for ($i = 0; $i -lt $Count; $i++) {
                    $Users.Add($TmpUsers[$i]) | Out-Null
                }
            } else {
                $Users = Invoke-MtGraphRequest -ApiVersion beta -RelativeUri 'users' -Select id, userPrincipalName, userType -Filter $queryFilter -QueryParameters @{'$top' = $Count } -DisablePaging -OutputType Hashtable
                $Users = $Users['value']
            }
        }

        return $Users
    }
}
