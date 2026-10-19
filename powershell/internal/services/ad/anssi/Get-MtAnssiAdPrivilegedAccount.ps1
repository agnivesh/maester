function Get-MtAnssiAdPrivilegedAccount {
    <#
    .SYNOPSIS
    Lists the privileged accounts of the collected domain.

    .DESCRIPTION
    A privileged account is a user or computer that reaches one of the groups Active Directory
    protects through AdminSDHolder (Administrators, Account Operators, Server Operators, Print
    Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain
    Controllers, Key Admins, and in the forest root domain Schema Admins, Enterprise Admins and
    Enterprise Key Admins), directly, through nested groups or through its primary group, plus the
    built-in Administrator and krbtgt accounts.

    The member lists are read over LDAP and kept for the session in the AD cache, so that the
    tests share the reads; Clear-MtADCache drops them. Throws when a member list cannot be read,
    or when Administrators or Domain Admins is not in the collected groups: a partial list is
    never returned as a complete one.

    .PARAMETER User
    The user accounts, as collected for the Users category.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .PARAMETER Group
    The groups, as collected for the Groups category.

    .PARAMETER DomainSid
    The SID of the collected domain.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdPrivilegedAccount -User $adState.Users -Computer $adState.Computers `
        -Group $adState.Groups -DomainSid $domainSid -ProtocolEvidence $adState.ProtocolEvidence

    Returns an object with Account (DistinguishedName, Kind, Item, Group, Link) and Unresolved
    (DistinguishedName, Group).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [AllowNull()]
        [object[]] $User,

        [AllowNull()]
        [object[]] $Computer,

        [AllowNull()]
        [object[]] $Group,

        [Parameter(Mandatory)]
        [string] $DomainSid,

        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $index = Get-MtAnssiAdDirectoryIndex -User $User -Computer $Computer -Group $Group `
        -DomainSid $DomainSid

    foreach ($requiredSid in 'S-1-5-32-544', "$DomainSid-512") {
        if ($null -eq $index.BySid[$requiredSid]) {
            throw ("The group $requiredSid is not in the collected groups: the privileged " +
                'accounts cannot be listed.')
        }
    }

    $protectedSid = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550',
        'S-1-5-32-551', 'S-1-5-32-552')
    foreach ($rid in 512, 516, 518, 519, 521, 526, 527) {
        $protectedSid += "$DomainSid-$rid"
    }
    $rootGroup = @(foreach ($sid in $protectedSid) {
            $entry = $index.BySid[$sid]
            if ($null -ne $entry) {
                $entry.Item
            }
        })

    $memberMap = Get-MtAnssiAdMemberMapCache -ProtocolEvidence $ProtocolEvidence
    Read-MtAnssiAdGroupMemberMap -GroupDn @($rootGroup.DistinguishedName) -Index $index `
        -MemberMap $memberMap -ProtocolEvidence $ProtocolEvidence

    $closure = Resolve-MtAnssiAdPrivilegedClosure -RootGroup $rootGroup -MemberMap $memberMap `
        -Index $index -DomainSid $DomainSid
    Write-Verbose ("Privileged accounts: $($closure.Account.Count), from $($rootGroup.Count) " +
        "protected group(s); unresolved members: $($closure.Unresolved.Count)")
    return $closure
}
