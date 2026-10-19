This test checks that no inbound trust relationship explicitly allows Kerberos delegation.

An inbound trust relationship means another domain or forest trusts the local domain, so accounts of the local domain can use resources of that third-party domain. By design, such a trust can allow delegating Kerberos tickets: a resource of the third-party domain then authenticates as the account that authenticated to it.

If delegation is allowed, a compromised resource of the third-party domain can impersonate the accounts that use it. This may lead to a privilege escalation from the third-party domain to the local domain.

#### Remediation action

Any inbound trust must deny Kerberos delegation to the trusting resource. On Windows Server 2012 and later, TGT delegation can be disabled for each trust relationship listed in the results with the following command:

```
netdom trust <domain> /domain:<trusted domain> /EnableTGTDelegation:no
```

#### How the test works

The test reads the trust objects of the domain and reports a trust relationship when both of the following apply:

- The trust is inbound or bidirectional (`trustDirection` is 1 or 3): another domain or forest trusts the local domain.
- Delegation is explicitly allowed: `CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION` (`0x800`) is set in `trustAttributes`.

Trust relationships without this flag are not reported. Outbound-only trust relationships are not reported either.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the trusts fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Inbound trust relationships with delegation](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_trusts_tgt_deleg)
- [MS-ADTS: trustAttributes](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c)

<!--- Results --->

%TestResult%
