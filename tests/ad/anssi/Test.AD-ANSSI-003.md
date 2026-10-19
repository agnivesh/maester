This test checks that no principal outside the privileged set can enroll in a certificate template that lets the requester name a certificate used to log on.

When a template lets the requester supply the subject or the subject alternative name, the CA does not check the name against the requester's account. Anyone who can enroll can ask for a certificate in the name of another user, a domain administrator included, and use it to log on to Windows as that user. If the right is granted to a broad group such as Authenticated Users, Domain Users or Domain Computers, any account of the forest can do it, and the whole forest can be compromised at once.

#### Severity

ANSSI gives this finding level 1 only, so every right the test reports is Critical. The result also names the templates that a CA trusted for logon publishes: for those the attack works today. The other templates are reported because they would work as soon as such a CA publishes them, and ANSSI does not exclude them.

#### Remediation action

ANSSI lists three ways to fix a template, by priority:

1. If the CA is not used for Windows smart card or RADIUS (PEAP or EAP-TLS) logon, remove it from the NTAuthCertificates container, for example with `pkiview.msc` or `certutil`. Do not confuse this container with Certification Authorities, which is used for CA trust. Removing a CA from NTAuthCertificates does not affect TLS authentication.
2. Stop the requester from supplying the subject: in the template properties (`certtmpl.msc`), have the CA build the name from Active Directory information instead of taking it from the request. Most of the time this is what the template needs.
3. If the template must let the requester supply the subject and the CA is trusted for Windows logon, give the enroll right to privileged principals only. Remove the other enroll entries with `pkiview.msc`, `adsiedit.msc` or `ldp.exe`.

#### How the test works

The test reads the certificate templates, the enrollment services that publish them, the certificates of the CAs and the NTAuthCertificates store of the forest. A template qualifies when both of these hold:

- The requester can name the certificate: `msPKI-Certificate-Name-Flag` has the subject bit (`0x1`) or the subject alternative name bit (`0x10000`). A template without that attribute does not qualify.
- The certificate can be used to log on: the extended key usage list holds Client Authentication, PKINIT Client Authentication, Smart Card Logon or Any Purpose, or is empty, which places no restriction on the use.

It then works out the privileged set as the other ANSSI permission tests do (the groups Active Directory protects with AdminSDHolder, their members, and a few system principals), and reports each allow entry that gives a principal outside that set the right to enroll on a qualifying template: the Certificate-Enrollment right, all extended rights, or full control. An earlier deny entry for the same principal, Everyone or Authenticated Users cancels the right.

A CA is trusted for logon when its certificate is one of the certificates of the NTAuthCertificates store, which is the list of CAs whose certificates Windows accepts for logon. Enterprise CAs add themselves to it. A template is published when the `certificateTemplates` attribute of an enrollment service names it.

Some things need a note:

- A template that holds all requests for a CA manager, or asks for authorized signatures, is still reported, because ANSSI does not exclude it. The result lists these templates, since the attack then needs an approval.
- The right to autoenroll and the right to read a template do not count. The rights to change a template are reported by ANSSI-AD-002.
- The result says how many members of the protected groups live outside the collected domain. Those were not checked.

Some things are not checked:

- The setting of a CA that lets requesters name the certificate on every template it publishes (`EDITF_ATTRIBUTESUBJECTALTNAME2`).
- Who may request certificates from a CA at all, which the permissions of the enrollment service and of the CA itself decide. A principal listed here can still be blocked there.
- Templates that only allow enrollment on behalf of another user, and the other ways to abuse a template.
- Certificate mapping on the domain controllers, which can make the attack harder.

The test runs against the forest root domain only: templates belong to the whole forest and their default permissions name the Domain Admins of the root domain. It is skipped there when a read fails, or when the permissions of a qualifying template cannot be read, rather than reporting a result. A forest without an enterprise CA has no NTAuthCertificates store: then no CA is trusted for logon, every finding is still reported as Critical, and none is named as working today.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous enrollment permission on authentication certificate templates](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_adcs_template_auth_enroll_with_name)
- [Microsoft Learn: ms-PKI-Certificate-Name-Flag attribute](https://learn.microsoft.com/windows/win32/adschema/a-mspki-certificate-name-flag)
- [Microsoft Learn: X509CertificateTemplateSubjectNameFlag enumeration](https://learn.microsoft.com/windows/win32/api/certenroll/ne-certenroll-x509certificatetemplatesubjectnameflag)
- [Microsoft Learn: X509CertificateTemplateEnrollmentFlag enumeration](https://learn.microsoft.com/windows/win32/api/certenroll/ne-certenroll-x509certificatetemplateenrollmentflag)
- [Microsoft Learn: Certificate-Enrollment extended right](https://learn.microsoft.com/windows/win32/adschema/r-certificate-enrollment)
- [Microsoft Learn: How to import third-party CA certificates into the Enterprise NTAuth store](https://learn.microsoft.com/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/import-third-party-ca-to-enterprise-ntauth-store)
- [Microsoft Learn: Smart card certificate requirements and enumeration](https://learn.microsoft.com/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)

<!--- Results --->

%TestResult%
