function Get-MtAnssiAdPrivilegedGpo {
    <#
    .SYNOPSIS
    Reads the group policy objects that apply to privileged accounts through their containers.

    .DESCRIPTION
    Reads the gPLink and gPOptions attributes of the domain root and of every container above the
    given accounts (with their owner and DACL, which other tests share through the session
    cache), works out the GPOs that apply with Get-MtAnssiAdAppliedGpo, and reads the owner,
    DACL and display name of each GPO of the domain. Returns an object with Gpo (the GPOs read,
    each with Name set to its display name followed by its directory name) and Note (a sentence
    giving the number of GPOs of another domain, which are not read, or an empty string). Throws
    when a read fails.

    .PARAMETER Account
    The distinguished names of the privileged accounts.

    .PARAMETER DomainDn
    The distinguished name of the domain root.

    .PARAMETER ProtocolEvidence
    The protocol evidence of the collected state, used to open the LDAP connection.

    .EXAMPLE
    Get-MtAnssiAdPrivilegedGpo -Account $dns -DomainDn $domainDn -ProtocolEvidence $evidence

    Returns the GPOs applied to the accounts.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Account,

        [Parameter(Mandatory)]
        [string] $DomainDn,

        [Parameter(Mandatory)]
        [object] $ProtocolEvidence
    )

    $container = @(Get-MtAnssiAdParentContainer -DistinguishedName $Account -DomainDn $DomainDn) +
    @($DomainDn)
    $containerObject = @(Get-MtAnssiAdObjectSecurity -DistinguishedName $container `
            -Attribute @('gPLink', 'gPOptions') -ProtocolEvidence $ProtocolEvidence)
    $applied = @(Get-MtAnssiAdAppliedGpo -DistinguishedName $Account -Container $containerObject `
            -DomainDn $DomainDn)
    $ignoreCase = [System.StringComparison]::OrdinalIgnoreCase
    $policies = ",CN=Policies,CN=System,$DomainDn"
    $inside = @($applied | Where-Object {
            $_.DistinguishedName.EndsWith($policies, $ignoreCase)
        })
    $gpoDn = @(foreach ($row in $inside) { $row.DistinguishedName })
    $gpo = @(Get-MtAnssiAdObjectSecurity -DistinguishedName $gpoDn `
            -Attribute @('displayName') -ProtocolEvidence $ProtocolEvidence)
    $named = foreach ($item in $gpo) {
        $copy = $item.PSObject.Copy()
        $copy.Name = "$($item.Attribute['displayName']) ($($item.Name))"
        $copy
    }

    $note = ''
    if ($applied.Count -gt $inside.Count) {
        $note = " $($applied.Count - $inside.Count) GPOs of another domain were not checked."
    }
    return [PSCustomObject]@{
        Gpo  = @($named)
        Note = $note
    }
}
