This test checks the certificates that Active Directory publishes to every computer of the forest for weak keys and signatures.

Certification authority certificates stored in the Configuration partition (the root CA store, the AIA objects, the NTAuth store and the enrollment services) are trusted by every domain member, and those in the NTAuth store are trusted to issue certificates for smart card and domain controller logon. If such a certificate has a key that can be broken or a signature that can be forged, an attacker can make certificates that the whole forest accepts, and log on as anyone.

#### What ANSSI says and how it rates the risk

ANSSI raises this finding at levels 1, 2 or 3: a DSA key, an RSA key under 1024 bits or the ROCA flaw is level 1, a certificate that cannot be parsed is level 2, and an RSA key under 2048 bits, a weak signature algorithm or a weak exponent is level 3.

Most findings are level 3 and a weak certificate alone is not a path to administrator rights, so the test is Medium. Level 1 findings are still shown as Critical in the results table.

#### Severity levels

In the Maester report the severity of this test is always Medium, lower than the most severe level it can raise: the Severity column of the results shows the level of each finding (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A DSA key, an RSA key under 1024 bits, or an RSA key with the ROCA weakness (CVE-2017-15361), whose private key can be computed from the public key | 1 | Critical |
| A certificate that cannot be parsed | 2 | High |
| An RSA key under 2048 bits, an RSA public exponent under 65537, or a signature hash other than SHA-2 or SHA-3 (for example MD5 or SHA-1) | 3 | Medium |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

For a certificate authority that is still in use, revoke the weak certificate, issue a new one with an RSA key of at least 2048 bits (or an elliptic curve key), the usual public exponent 65537 and a SHA-2 signature, from an up-to-date library, then reissue the certificates it signed. Remove expired certificates and those of authorities that are no longer used from the containers listed in the results, with the Enterprise PKI console (`pkiview.msc`, Manage AD Containers) or, for the NTAuth store, with:

```
certutil -viewdelstore "ldap:///CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com?cACertificate?base?objectclass=certificationAuthority"
```

Back up each object before you change it: a certificate that is still needed to validate issued certificates breaks those certificates once removed.

#### How the test works

The test searches the Services container of the Configuration partition for objects with a `cACertificate` value and checks each certificate, expired ones included: the key type, the RSA key length and public exponent, the ROCA fingerprint (the published test of the researchers who found the weakness, written into the test), and the signature algorithm, including the hash named in the parameters of an RSASSA-PSS signature. A certificate found in several places is listed once per place. Elliptic curve keys are only judged by their signature.

Some things are not checked:

- certificates held in other attributes, such as the user certificates of accounts and the key recovery agent certificates;
- the certificates installed on the CA servers themselves, and certificates spread through Group Policy;
- whether a certificate is revoked.

If a read fails, the test is skipped rather than reporting a result.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Weak or vulnerable certificates](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_certificates_vuln)
- [Microsoft Learn: Monitor AD CS publication health with Enterprise PKI](https://learn.microsoft.com/windows-server/identity/ad-cs/monitor-ad-cs-health-enterprise-pki)
- [Microsoft Learn: Decommission an enterprise CA and remove its objects](https://learn.microsoft.com/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/decommission-enterprise-certification-authority-and-remove-objects)
- [ROCA detection tools and research (crocs-muni/roca)](https://github.com/crocs-muni/roca)

<!--- Results --->

%TestResult%
