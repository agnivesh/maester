This test checks that no outbound forest trust relationship has SID history enabled, that is that forest trusts keep their default filtering.

An outbound forest trust means the local forest trusts the other forest. This extends the security boundary of the local forest to include the trusted forest. By default, forest trusts are filtered more strictly than external trusts. This filtering can be relaxed so that the forest trust is treated like an external trust and the SID history mechanism is enabled, for example during a migration.

When the filtering is relaxed, the trusting forest is endangered by the trusted forest. An attacker having compromised the trusted forest can spoof any user or computer of the local forest, except accounts with a RID lower than 1000 (built-in accounts and groups). This attacker can therefore access every resource of the local forest. If a dangerous control path is exposed to any "spoofable" account (virtually any account other than the built-in ones), the attacker could also escalate privileges up to "Domain Admins" and compromise the entire forest.

#### Remediation action

First clarify the rationale behind the current configuration. SID history may have been enabled on purpose for an ongoing migration that requires it.

Otherwise, restore the default filtering of each forest trust listed in the results:

```
netdom trust <forest> /domain:<other trusted forest> /EnableSIDHistory:no
```

#### How the test works

The test reads the trust objects of the domain and reports a trust relationship when all of the following apply:

- The trust is outbound or bidirectional (`trustDirection` is 2 or 3): the local forest trusts the other forest.
- The trust is a forest trust: `FOREST_TRANSITIVE` (`0x8`) is set in `trustAttributes`.
- The filtering is relaxed: `TREAT_AS_EXTERNAL` (`0x40`) is set in `trustAttributes`. When `PIM_TRUST` (`0x400`) is also set, the trust is treated as a Privileged Identity Management trust for SID filtering.

Inbound-only trusts are not reported: with an inbound trust, the other forest is the one that trusts the local forest. Trusts to domains outside of the forest that are not forest trusts are evaluated by ANSSI-AD-035.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the trusts fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Outbound forest trust relationships with sID History enabled](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_trusts_forest_sidhistory)
- [MS-ADTS: trustAttributes](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c)

<!--- Results --->

%TestResult%
