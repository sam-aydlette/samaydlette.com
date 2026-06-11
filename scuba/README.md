# SCuBA — customer-run secure-configuration assessment

A customer-run tool (pattern after CISA's SCuBA / ScubaGoggles) that assesses a
customer's **configuration of their responsibilities** when consuming this cloud
service offering — and reports, for each check, *which framework requirements it
satisfies*.

## How it works (read-only, nothing leaves your environment)
1. Fetch the **signed policy bundle** (in production: from `/.well-known/`, then
   `cosign verify`; here: the local `scuba/` bundle).
2. The CLI evaluates each policy **locally with OPA** against *your* config.
3. Each policy maps to an **800-53 Rev5 control** (the hub); the CLI projects that
   control to every framework via the published control mappings — **one config
   check → N frameworks**.
4. Output: an **OSCAL Assessment Results** document + a terminal report.

It **flags, it does not bless**: a pass means "this config satisfies the mapped
control" — evidence, not an authorization.

## Run
```bash
python3 scuba/scuba.py --config your-config.json --output results.json
# demo:
python3 scuba/scuba.py --config scuba/sample-config.json --output /tmp/results.json
```

## A policy
Each policy is `policies/<name>.rego` (the OPA check) + `policies/<name>.md` (the
human SCB description), with metadata (id, title, 800-53 control, severity) in
`bundle.json`. Adding a policy = a Rego file + a markdown doc + a manifest entry;
its framework reach comes for free from the hub crosswalks.

## Why this is the CRM's executable layer
This replaces a static Customer Responsibility Matrix with an **assessable** one:
the matrix tells you what you own; the SCuBA lets you *check* it. Grounded in
FedRAMP 20x Secure Configuration Guidance enhanced capabilities (SCG-ENH-MRG /
SCG-ENH-CMP / SCG-ENH-API) — the SCuBA pattern, named.

## Status (demonstration)
2 representative policies (phishing-resistant MFA → IA-2(1); TLS → SC-8).
Framework projection currently lights up 800-53 Rev5/Rev4 + FedRAMP Moderate;
CMMC / GovRAMP / TX-RAMP / IRAP light up automatically as their control mappings
land at each spoke checkpoint. Bundle **signing** (Sigstore) + publication at
`/.well-known/` is the next wiring step.
