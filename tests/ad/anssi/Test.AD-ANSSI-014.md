This test checks that the DNS zones stored in Active Directory accept only secure dynamic updates.

With dynamic updates, computers register and refresh their own DNS records. When a zone accepts "nonsecure and secure" updates, any device on the network can add a record or replace an existing one without authenticating. An attacker can then point a well-known name, such as a file server, a proxy or an administration console, to a machine of their own and wait for users and administrators to connect and hand over their credentials. With "secure only", a record can be changed only by an authenticated account that has the right to do so.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| The zone of the domain, or the `_msdcs` zone of the forest (which locates the domain controllers), accepts nonsecure updates | 1 | Critical |
| Any other zone stored in Active Directory accepts nonsecure updates | 3 | Medium |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Set each zone listed in the results to accept secure dynamic updates only, in the DNS Manager console (zone properties, General tab, Dynamic updates: Secure only) or with:

```
dnscmd <servername> /Config <zone> /AllowUpdate 2
```

The setting is stored in Active Directory, so changing it on one DNS server applies to all servers that load the zone.

#### How the test works

The test searches the domain naming context (below `CN=System`, where older zones are kept) and the DomainDnsZones and ForestDnsZones partitions, when the domain controller lists them, for DNS zone objects. For each zone it decodes the `dNSProperty` values as Microsoft documents them and reads the dynamic update setting (property `DSPROPERTY_ZONE_ALLOW_UPDATE`): 1 means nonsecure and secure updates. Zones whose name starts with two dots, which the DNS server uses for deleted zones and trust anchors, are left out. The zone of the domain and the `_msdcs` zone of the forest are compared by name.

Some things are not checked:

- zones that are not stored in Active Directory (file-backed primary or secondary zones on a DNS server);
- the permissions on the zones and their records;
- zones of other domains of the forest stored in their own domain partition.

If a read fails, the test is skipped rather than reporting a result. The test is also skipped when no DNS zone stored in Active Directory is visible: an account without read access sees nothing, and a pass would then say nothing about the domain.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Misconfigured DNS zones](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_dnszone_bad_prop)
- [Microsoft Learn: MS-DNSP, dnsProperty](https://learn.microsoft.com/openspecs/windows_protocols/ms-dnsp/445c7843-e4a1-4222-8c0f-630c230a4c80)

<!--- Results --->

%TestResult%
