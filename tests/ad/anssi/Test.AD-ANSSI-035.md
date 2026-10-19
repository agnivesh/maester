This test checks that every outbound trust relationship from the domain to a domain outside of the forest is quarantined, which means SID filtering is enabled on the trust.

An outbound trust means the local domain trusts the other domain, so the accounts of the trusted domain can be granted access to resources of the local domain. This extends the security boundary of the local domain to include the trusted domain. Quarantine, also called SID filtering, keeps that boundary under control: it prevents users of the trusted domain from presenting the identity of a user of another domain. It must be enabled on each relevant trust relationship individually.

Without quarantine, an attacker having compromised the trusted domain can spoof any user or computer of the local domain, except accounts with a RID lower than 1000 (built-in accounts and groups). This attacker can therefore access every resource of the local domain. If a dangerous control path is exposed to any "spoofable" account (virtually any account other than the built-in ones), the attacker could also escalate privileges up to "Domain Admins" and compromise the entire forest.

#### Remediation action

Enable quarantine on each trust relationship listed in the results:

```
netdom trust <local domain> /domain:<external trusted domain> /Quarantine:yes
```

Setting up outbound trust relationships to domains with a lower trust level is strongly discouraged. Remove trust relationships that are no longer needed.

Before enabling quarantine, confirm that no ongoing migration relies on SID history across the trust. SID filtering discards the SIDs that do not belong to the trusted domain, including SID history.

#### How the test works

The test reads the trust objects of the domain and reports a trust relationship when all of the following apply:

- The trust is outbound or bidirectional (`trustDirection` is 2 or 3): the local domain trusts the other domain.
- The trust is to a Windows domain (`trustType` is 1 or 2). MIT and DCE realm trusts carry no SIDs.
- The trust is not quarantined: `QUARANTINED_DOMAIN` (`0x4`) is not set in `trustAttributes`.
- The trust is not within the forest: `WITHIN_FOREST` (`0x20`) is not set in `trustAttributes`.
- The trust is not a forest trust: `FOREST_TRANSITIVE` (`0x8`) is not set in `trustAttributes`. Forest trusts are filtered by default and are not evaluated by this test.

Each trust relationship type is defined by flags set within some LDAP attributes of the trust object. In some cases, particularly with legacy forests, internal trust relationships may not bear the `WITHIN_FOREST` flag. These relationships are reported by this test. If a reported trust is internal to the forest, its flags must be corrected on the trust object.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the trusts fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Unfiltered outbound domain trust relationship](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_trusts_domain_notfiltered)
- [MS-ADTS: trustAttributes](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c)

<!--- Results --->

%TestResult%
