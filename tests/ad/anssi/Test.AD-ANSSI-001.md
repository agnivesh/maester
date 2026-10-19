This test checks that only privileged principals control the certificate containers and the CA objects of the forest.

A certification authority (CA) signs certificates that every domain member trusts, including certificates that can be used to log on. The forest lists its CAs in the Public Key Services containers of the Configuration partition: the Certification Authorities container holds the CAs that clients trust, the NTAuthCertificates object lists the CAs that Windows accepts for logon, and the Enrollment Services container holds the CAs that issue certificates. Someone who can write to these containers can add a malicious CA, or list one as trusted for logon, and then authenticate as any user or service.

#### Severity levels

ANSSI gives this finding level 1 only, so every finding is reported as Critical.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set and the expected CA accounts owns one of these objects, or holds full control, the right to change its permissions or owner, to write all its attributes, to write its list of CA certificates, or to create child objects in it | 1 | Critical |

A passing result is reported as Critical too.

#### Remediation action

Remove the entries listed in the results from the containers and objects, with `adsiedit.msc` or `ldp`, to bring them back to their default state. A user who installs a Microsoft PKI server is given rights on these containers automatically, so check which accounts did the installation and whether they still need the rights. An account or group that has to manage the PKI, for example a PKI administrators group, must be treated as privileged and protected like the other administrators.

#### How the test works

The test reads the owner and the permissions of every object below `CN=Public Key Services` in the Configuration partition that is a container, a certification authority object (the CA certificates and the NTAuthCertificates store), an enrollment service, a CRL distribution point or a key recovery agent. The certificate templates are covered by ANSSI-AD-002 and ANSSI-AD-003.

It works out the privileged set as the other ANSSI permission tests do: the groups Active Directory protects with AdminSDHolder, their members (nested and through primary groups), and a few system principals that Windows trusts by default. A default CA installation is also expected, so two more kinds of principals are accepted:

- the Cert Publishers group of the domain (RID 517), which holds full control of the AIA and CRL objects and of the CA objects of the servers that publish to them;
- the computer account of each CA server, found from the `dNSHostName` of its enrollment service, which holds full control of its own objects.

An allow entry for any other principal is reported when it grants one of these rights: full control, the right to change permissions, the right to change the owner, writing all attributes, writing the `cACertificate` attribute, or creating child objects. An earlier deny entry for the same principal, Everyone or Authenticated Users cancels the right. An owner outside that set is reported too. Reading and enrolling are not reported.

Things to keep in mind:

- The Cert Publishers group is accepted as it is, so its members are trusted: they are the CA servers, which need the same protection as domain controllers.
- A CA server that is not in the collected domain (a CA in a child domain, for example) is not recognized, so its account appears in the results as a SID.
- A group that was given rights on purpose, such as a PKI administrators group, is reported. ANSSI asks to revert the containers to their default state.
- The test does not check who administers the CAs themselves (the CA roles Manage CA and Issue and Manage Certificates), the local administrators of the CA servers, or the settings of a CA such as `EDITF_ATTRIBUTESUBJECTALTNAME2`.
- The result says how many members of the protected groups live outside the collected domain. Those were not checked.

The test runs against the forest root domain only, since the containers belong to the whole forest and their default permissions name the Domain Admins of the root domain. If a read fails, or the permissions of an object cannot be read, the test is skipped rather than reporting a result. The test is also skipped when no PKI container is visible: the Public Key Services container exists in every forest, so none visible means that the account cannot read it.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose certificate containers](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_adcs_control)
- [Microsoft Learn: Monitor AD CS publication health with Enterprise PKI](https://learn.microsoft.com/windows-server/identity/ad-cs/monitor-ad-cs-health-enterprise-pki)
- [Microsoft Learn: How to import third-party CA certificates into the Enterprise NTAuth store](https://learn.microsoft.com/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/import-third-party-ca-to-enterprise-ntauth-store)
- [Microsoft Learn: CA-Certificate attribute](https://learn.microsoft.com/windows/win32/adschema/a-cacertificate)

<!--- Results --->

%TestResult%
