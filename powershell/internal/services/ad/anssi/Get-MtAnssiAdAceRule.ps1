function Get-MtAnssiAdAceRule {
    <#
    .SYNOPSIS
    Returns the table of dangerous rights that the ANSSI permission checks look for.

    .DESCRIPTION
    Each row names a control, its ANSSI level (1: usable without a major prerequisite, 2:
    potentially dangerous), the access mask bits it needs (all of them), the object type GUID
    the entry must carry ('' for an entry without object type, '*' for any) and, when the right
    only matters on some object classes, those classes (a case-insensitive set, $null for any).
    Rows are ordered so that the first matching row is the most telling control of an entry.
    Creating child objects matters on
    containers that hold sensitive children: plain containers, GPOs, naming context roots, the
    schema, and the DFSR objects of a replication group (adding a member to the SYSVOL
    replication group is creating a child object).
    On a certificate template, writing any one attribute is level 1: a single attribute, such as
    the name flags or the extended key usages, can turn the template into one that issues
    certificates for any user. An entry whose object type is the Certificate-Enrollment or
    Certificate-AutoEnrollment right (the standard enrollment entry, mask 0x130) is not a write
    right on an attribute: the row lists those GUIDs in IgnoreType ($null for the other rows).

    Rights and GUIDs (Microsoft Learn, Active Directory schema): member bf9679c0 (also the
    Self-Membership validated write), User-Force-Change-Password 00299570,
    DS-Replication-Get-Changes-All 1131f6ad, msDS-KeyCredentialLink 5b47d60f,
    msDS-AllowedToActOnBehalfOfOtherIdentity 3f78c3e5, gPLink f30e3bbe, gPCFileSysPath f30e3bc1,
    servicePrincipalName and Validated-SPN f3a64788, altSecurityIdentities 00fbf30c,
    Public-Information property set e48d0154, managedBy 0296c120.

    .EXAMPLE
    Get-MtAnssiAdAceRule

    Returns the rows in matching order.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $container = @('container', 'groupPolicyContainer', 'domainDNS', 'configuration', 'dMD',
        'msDFSR-ReplicationGroup', 'msDFSR-Topology', 'msDFSR-Content', 'msDFSR-LocalSettings',
        'msDFSR-Subscriber')
    $enrollmentRight = @('0e10c968-78fb-11d2-90d4-00c04f79dc55',
        'a05b8cc2-17bc-4802-a710-e7c15ab866a2')
    $rows = @(
        , @('GenericAll', 1, 0x10000000, '*', $null)
        , @('GenericAll', 1, 0xF01FF, '*', $null)
        , @('WriteDacl', 1, 0x40000, '*', $null)
        , @('WriteOwner', 1, 0x80000, '*', $null)
        , @('GenericWrite', 1, 0x40000000, '*', $null)
        , @('GenericWrite', 1, 0x20, '', $null)
        , @('AllExtendedRights', 1, 0x100, '', $null)
        , @('ResetPassword', 1, 0x100, '00299570-246d-11d0-a768-00aa006e0529', $null)
        , @('Replication', 1, 0x100, '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', $null)
        , @('WriteMember', 1, 0x20, 'bf9679c0-0de6-11d0-a285-00aa003049e2', $null)
        , @('WriteMember', 1, 0x8, 'bf9679c0-0de6-11d0-a285-00aa003049e2', $null)
        , @('WriteMember', 1, 0x8, '', @('group'))
        , @('KeyCredentialLink', 1, 0x20, '5b47d60f-6090-40b2-9f37-2a4de88f3063', $null)
        , @('ResourceDelegation', 1, 0x20, '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79', $null)
        , @('GpLink', 1, 0x20, 'f30e3bbe-9ff0-11d1-b603-0000f80367c1', $null)
        , @('GpoFilePath', 1, 0x20, 'f30e3bc1-9ff0-11d1-b603-0000f80367c1', $null)
        , @('WriteTemplateProperty', 1, 0x20, '*', @('pKICertificateTemplate'), $enrollmentRight)
        , @('WriteSpn', 2, 0x20, 'f3a64788-5306-11d1-a9c5-0000f80367c1', $null)
        , @('WriteSpn', 2, 0x8, 'f3a64788-5306-11d1-a9c5-0000f80367c1', $null)
        , @('AllValidatedWrites', 2, 0x8, '', $null)
        , @('WriteAltIdentity', 2, 0x20, '00fbf30c-91fe-11d1-aebc-0000f80367c1', $null)
        , @('WritePublicInformation', 2, 0x20, 'e48d0154-bcf8-11d1-8702-00c04fb96050', $null)
        , @('WriteManagedBy', 2, 0x20, '0296c120-40da-11d1-a9c0-0000f80367c1', $null)
        , @('CreateChild', 2, 0x1, '*', $container)
    )
    foreach ($row in $rows) {
        $class = $null
        if ($null -ne $row[4]) {
            $class = [System.Collections.Generic.HashSet[string]]::new([string[]]$row[4],
                [System.StringComparer]::OrdinalIgnoreCase)
        }
        [PSCustomObject]@{
            Control    = $row[0]
            Level      = $row[1]
            Mask       = [uint32]$row[2]
            ObjectType = $row[3]
            Class      = $class
            IgnoreType = $row[5]
        }
    }
}
