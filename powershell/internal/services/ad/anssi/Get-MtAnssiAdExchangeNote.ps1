function Get-MtAnssiAdExchangeNote {
    <#
    .SYNOPSIS
    Explains the rights that Exchange groups hold, when a result lists one of them.

    .DESCRIPTION
    Exchange's default (shared permissions) setup gives its security groups wide rights in the
    directory, mostly on the domain object, where they are inherited by every user and group
    that does not block inheritance. Attackers have used these rights to take over accounts and,
    in the 2019 PrivExchange attack, the domain. Microsoft's remedy is Active Directory split
    permissions. When one of the trustees in a result is Exchange Trusted Subsystem, Exchange
    Windows Permissions, Organization Management or Exchange Servers, this function returns a
    short note that names the groups found, the cause and the remedy, with a link to Microsoft
    Learn. It returns an empty string when none of them is listed. Names are matched exactly, in
    the English names that Exchange creates, without regard to case.

    .PARAMETER Trustee
    The names shown for the trustees of a result, as built by Format-MtAnssiAdAceControlTable.

    .EXAMPLE
    Get-MtAnssiAdExchangeNote -Trustee @('alice', 'Exchange Servers')

    Returns the note for the Exchange Servers group.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]] $Trustee
    )

    $known = 'Exchange Trusted Subsystem', 'Exchange Windows Permissions',
    'Organization Management', 'Exchange Servers'
    $found = foreach ($name in $known) {
        if ($Trustee -contains $name) { $name }
    }
    if (-not $found) { return '' }

    return "Exchange groups among the trustees: $(@($found) -join ', '). Exchange's default " +
        'setup (the shared permissions model) gives these groups wide rights in the directory, ' +
        'which attackers have used to take over accounts and, in the 2019 PrivExchange attack, ' +
        'the domain. Active Directory split permissions remove the entries that Exchange adds ' +
        'for its security groups on the domain object: ' +
        'https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions'
}
