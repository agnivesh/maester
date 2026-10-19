function Get-MtAnssiAdDfsrSysvolObject {
    <#
    .SYNOPSIS
    Reads the owner and DACL entries of the DFSR objects that replicate SYSVOL.

    .DESCRIPTION
    Finds the DFSR replication group named Domain System Volume below CN=System of the domain and
    reads every object of it (topology, members, content set), then reads the DFSR local
    settings, subscriber and subscription objects below each domain controller account (found
    with Get-MtAnssiAdDomainController, writable and read-only). Uses
    Get-MtAnssiAdSearchSecurity, so reads are kept for the session. Returns the objects found,
    nothing when SYSVOL is not replicated with DFSR. Throws when a search fails.

    .PARAMETER DomainDn
    The distinguished name of the domain root.

    .PARAMETER Computer
    The collected computers.

    .PARAMETER DomainController
    The collected domain controllers (NTDS settings objects).

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdDfsrSysvolObject -DomainDn $domainDn -Computer $adState.Computers `
        -DomainController $adState.DomainControllers -ProtocolEvidence $evidence

    Returns the DFSR objects of SYSVOL.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string] $DomainDn,

        [AllowNull()]
        [object[]] $Computer,

        [AllowNull()]
        [object[]] $DomainController,

        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $group = @(Get-MtAnssiAdSearchSecurity -SearchBase @("CN=System,$DomainDn") -Scope Subtree `
            -Filter '(&(objectClass=msDFSR-ReplicationGroup)(cn=Domain System Volume))' `
            -ProtocolEvidence $ProtocolEvidence)
    $groupDn = @(foreach ($item in $group) { $item.DistinguishedName })
    if ($groupDn.Count -gt 0) {
        Get-MtAnssiAdSearchSecurity -SearchBase $groupDn -Scope Subtree -Filter '(objectClass=*)' `
            -ProtocolEvidence $ProtocolEvidence
    }
    $controllerDn = @(foreach ($item in @(Get-MtAnssiAdDomainController -Computer $Computer `
                    -DomainController $DomainController)) { $item.Computer.DistinguishedName })
    if ($controllerDn.Count -gt 0) {
        $local = '(|(objectClass=msDFSR-LocalSettings)(objectClass=msDFSR-Subscriber)' +
        '(objectClass=msDFSR-Subscription))'
        Get-MtAnssiAdSearchSecurity -SearchBase $controllerDn -Scope Subtree -Filter $local `
            -ProtocolEvidence $ProtocolEvidence
    }
}
