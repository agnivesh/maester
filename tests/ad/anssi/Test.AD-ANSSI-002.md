This test checks that only privileged principals can change the certificate templates of the forest.

A certificate template tells an enterprise CA what to put in the certificates it issues and who may ask for them. Someone who can change a template can, for example, let the requester choose the name in the certificate and add client authentication to its uses, then ask for a certificate in the name of a domain administrator and log on as them. Templates are stored once for the whole forest, so a change reaches every CA that publishes them.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set can take control of a template that a CA publishes: full control, write the permissions, the owner or any attribute, or it owns the template | 1 | Critical |
| The same on a template no CA publishes, or a less direct right on any template | 2 | High |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Open the Certificate Templates console (`certtmpl.msc`), and on the Security tab of each template listed in the results remove the rights of the principal named, or give the template a privileged owner. Keep Read for Authenticated Users (the CA needs it) and grant Enroll only to the groups that need the certificate. Templates that no CA publishes can still be published later: fix them too, or delete those that are no longer needed.

#### How the test works

The test runs only against the forest root domain: templates are shared by the whole forest and their default permissions name the Domain Admins of the forest root domain, which a child domain cannot identify. Elsewhere it is skipped.

It searches the Services container of the Configuration partition for certificate templates and enrollment services. A template is published when an enrollment service lists it. For each template it reads the owner and the permissions, works out the privileged set as the other ANSSI permission tests do, and reports each right from a fixed list held by a principal outside that set, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. On a template, the right to write even one attribute is reported, because a single attribute can change who the certificates are issued for.

Some things are not checked:

- enrollment rights (who may request a certificate) and the settings of the templates themselves;
- the permissions on the CA, its enrollment service object and the containers above the templates.

If a read fails or the permissions of a template could not be read, the test is skipped rather than reporting a result.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs on certificate templates](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_adcs_template_control)
- [Microsoft Learn: Certificate templates concepts](https://learn.microsoft.com/windows-server/identity/ad-cs/certificate-template-concepts)
- [Microsoft Learn: Manage AD CS certificate templates on an enterprise CA](https://learn.microsoft.com/windows-server/identity/ad-cs/manage-certificate-templates)

<!--- Results --->

%TestResult%
