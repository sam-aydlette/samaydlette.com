# Information Sharing and Disclosure Standard

This standard says what certification data is published, what is never published, and why publishing it is not likely to harm the offering. It implements CDS-CSO-RIS and records the determination CDS-CSO-RPS permits. Decision record: DEC-166.

**What is public.** The whole FedRAMP certification package: every artifact the signed manifest (https://samaydlette.com/.well-known/trust-manifest.json) lists, the policies and procedures it links, and the repository that builds them. It is public because the offering has no federal data and no agency sponsor, and because showing the evidence openly is the purpose of this proof of concept. Anyone may read, download and verify it.

**What is never published.** The deploy refuses to publish, and the gates named here fail the build on:

- AWS account IDs, and ARNs that carry one (publication redaction gate, `scripts/check-published-redaction.py`; ARNs are published with the account replaced by `ACCOUNT`);
- secret values, keys, tokens and credentials of any kind (never placed in the inventory; Terraform state is read owner-only and deleted after use);
- personal email addresses and IAM user names (the rule records, trust center and boundary map refuse them);
- GitHub run IDs and raw logs, including CloudFront access logs: only aggregate counts are published (CDS-TRC-ACL);
- the contacts behind an agency access request: the register names agencies and systems, never people.

**What is public on purpose, after consideration.** Some published detail could look sensitive. Each is published because an authorizing official needs it to judge the system, and none grants access by itself:

- IAM role names and summaries of their least-privilege policies: they show who can change what; assuming a role needs the GitHub OIDC trust bound to this repository's reviewed environment;
- the API Gateway endpoint host and the CloudFront domain: both are already discoverable through DNS and every page load;
- component configuration, scanner findings with their dispositions, and vulnerability reports: they show how the system is built and how each finding was decided, which an authorizing official cannot judge without.

**Determination.** The operator has determined that sharing the package publicly in this form is not likely to have an adverse effect on the offering, because it carries none of the items listed above and the items published on purpose give no access on their own. The determination is re-checked by machine: the redaction gate (`scripts/check-published-redaction.py`) screens every published file on every publish, and a new kind of artifact is a pull request that adds it to the publishers' lists, where this determination is revisited.

**Verification.** Machine-checked on every deploy and every night (`scripts/check-non-machine-vv.py`), and re-checked, with its sha256, in each Annual Security Review (`scripts/hold-security-review.py`); a change is a reviewed pull request.
