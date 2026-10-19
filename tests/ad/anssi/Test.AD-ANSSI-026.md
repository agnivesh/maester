This test checks that only privileged principals can control the Key Distribution Service (KDS) root keys of the forest.

Group managed service accounts (gMSA) get passwords that nobody has to type or store: domain controllers compute them on demand from a KDS root key, kept in the Configuration partition of the forest. Whoever can read a root key can compute the current and future password of every gMSA that uses it, and many gMSAs run services with high privileges. Whoever controls the key objects, or the container that holds them, can give themselves that read access. By default only Enterprise Admins, Domain Admins and Local System have rights on the keys.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set owns a root key or the Master Root Keys container, or holds full control, all extended rights, the right to change its permissions or owner, to write all its attributes, or another right usable without a major prerequisite | 1 | Critical |
| A principal outside the privileged set holds another potentially dangerous right on it, such as creating child objects in the container | 2 | High |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Bring the objects listed in the results back to their default permissions, for example with ADSI Edit, or with `dsacls <DN> /S /T`, which restores the defaults defined in the schema. If a principal really needs rights there, treat it as an administrator and protect it with AdminSDHolder.

#### How the test works

The test reads the RootDSE to find the Configuration partition and searches `CN=Services` in it for the `Master Root Keys` container and the root key objects (class msKds-ProvRootKey), which Microsoft documents below `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services`. A forest without root keys has only the container, or nothing, to check. It works out the privileged set as the other ANSSI permission tests do and reports each right from a fixed list held by a principal outside that set, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. An owner outside the privileged set is reported too. The key data is a confidential attribute: reading it needs extended rights, which the list covers.

Some things are not checked:

- the gMSA accounts themselves and who may retrieve their passwords (msDS-GroupMSAMembership);
- deny entries for other groups, which can only make the test report more than needed;
- members of the protected groups that live outside the collected domain. The results say how many there were.

These objects belong to the whole forest. The test takes the SID of the forest root domain from the domain itself, or, in a child domain, from the trust to the parent domain, and trusts that domain's Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins groups, as it does for the domain it runs in, so that running it from a child domain does not report the default permissions of the forest root. The Domain Admins group of the domain the test runs in stays trusted as well, so a right held by it on these objects is not reported. If the SID of the forest root domain cannot be found, for example in a grandchild domain, which has no trust to the root, the test is skipped.

If a read fails, or the permissions of an object cannot be read, the test is skipped rather than reporting a result. The test is also skipped when no KDS container is visible at all. In the Windows Server 2019 lab forest used for testing, the Master Root Keys container was present although no root key had been created (Maester's own observation, not a documented guarantee), so none visible most likely means that the account cannot read it, or that the forest predates the KDS.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose gMSA key objects](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_gmsa_keys)
- [Microsoft Learn: Create the Key Distribution Services KDS root key](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key)

<!--- Results --->

%TestResult%
