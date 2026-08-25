# Makefile for local infrastructure work and the offline compliance gates.
#
# THIS MAKEFILE NEVER PUBLISHES. Nothing here writes to the website bucket or to
# /.well-known/. Artifact generation, cosign signing, the reconciliation gate and
# the publish step all live in .github/workflows/deploy-with-opa.yml, where the
# `deploy` job is bound to the `prod` GitHub Environment and halts for a human
# reviewer before `terraform apply`.
#
# That separation is the point. A local publish path would put an unsigned,
# unreconciled, partial artifact set over the CI-published one, breaking the
# cross-artifact signal_id binding on the live site with the gate that exists to
# catch exactly that never having run. The sync targets that used to live here
# did precisely that, and worse: they synced `.` (this directory) rather than
# `website/`, with --delete and no .well-known/ exclusion.

.PHONY: a11y help init plan apply-infra deploy destroy check-compliance build-ksi-signal build-oscal-ssp clean gate python-test figures-check reconcile verify-published test-policies fmt security-scan validate outputs status dev-setup pipeline create-cert

# Default target
help:
	@echo "Available targets:"
	@echo "  init             - Initialize Terraform and install dependencies"
	@echo "  plan             - Run Terraform plan with OPA compliance check"
	@echo "  apply-infra      - Apply the reviewed plan. Infrastructure only; publishes nothing."
	@echo "  pipeline         - init + validate + plan + apply-infra"
	@echo "  check-compliance - Invoke the compliance Lambda (read-only)"
	@echo "  reconcile        - Cross-artifact reconciliation gate (RECONCILE_FLAGS=--live)"
	@echo "  verify-published - Fetch and verify the LIVE published evidence"
	@echo "  gate / python-test / test-policies / a11y / figures-check - offline gates"
	@echo "  destroy          - Destroy all infrastructure"
	@echo "  clean            - Clean temporary files"
	@echo ""
	@echo "Publishing to /.well-known/ happens in CI only. There is no local publish target."
	@echo ""
	@echo "Environment variables:"
	@echo "  DOMAIN_NAME      - Domain name (default: samaydlette.com)"
	@echo "  ENVIRONMENT      - Environment name (default: prod)"

# Variables
DOMAIN_NAME ?= samaydlette.com
ENVIRONMENT ?= prod

# Initialize Terraform and dependencies
init:
	@echo "Initializing Terraform..."
	terraform init
	@echo "Installing Lambda dependencies..."
	cd lambda && npm install --production
	@echo "Checking for OPA..."
	@if ! command -v opa >/dev/null 2>&1; then \
		echo "Installing OPA..."; \
		curl -L -o opa https://openpolicyagent.org/downloads/v1.18.2/opa_linux_amd64_static; \
		echo "9903e5125ac281104f2c4b7371d10cc3b74a98933743fcbfc174f9bf0ab20de8  opa" | sha256sum -c -; \
		chmod 755 ./opa; \
		sudo mv opa /usr/local/bin; \
	fi
	@echo "✅ Initialization complete"

# Run Terraform plan with compliance check
plan:
	@echo "Running Terraform plan with OPA compliance check..."
	@if [ ! -f terraform.tfvars ]; then \
		echo "❌ terraform.tfvars not found. Copy terraform.tfvars.example and customize it."; \
		exit 1; \
	fi
	./terraform-plan.sh

# Apply the reviewed plan. INFRASTRUCTURE ONLY — this publishes nothing.
#
# The old `deploy` target also uploaded content and artifacts. It is gone: it
# synced `.` (infrastructure/) rather than website/ into the bucket root with
# --delete and no .well-known/ exclusion, so it removed the whole site and the
# published evidence and uploaded build junk in its place. CI does the equivalent
# sync correctly (website/, --exclude ".well-known/*") and every artifact under
# /.well-known/ is published there by an explicit, signed, post-gate step.
apply-infra:
	@echo "Applying infrastructure..."
	@if [ ! -f tfplan ]; then \
		echo "❌ No Terraform plan found. Run 'make plan' first."; \
		exit 1; \
	fi
	terraform apply tfplan
	@echo "✅ Infrastructure applied. Nothing was published —"
	@echo "   content and /.well-known/ artifacts are published by CI, behind"
	@echo "   the reconciliation gate and the prod environment approval."

# Kept as an alias so muscle memory does not silently do nothing, but it no
# longer deploys content. Publishing is not available locally by design.
deploy:
	@echo "❌ 'make deploy' has been removed."
	@echo ""
	@echo "   Infrastructure only:  make apply-infra"
	@echo "   Publishing:           push to main and approve the prod environment"
	@echo ""
	@echo "   Local publishing is deliberately unavailable: it bypassed the"
	@echo "   reconciliation gate and put a partial, unsigned artifact set over"
	@echo "   the CI-published one."
	@exit 1

# Build the deploy-time KSI signal (ksi-signal.json) by joining Terraform state,
# the Lambda's package-lock, the website's HTML hashes, the CI provenance, and
# the OPA validations from terraform-plan.sh. Writes a local file; publishes nothing.
build-ksi-signal:
	@echo "Building deploy-time KSI signal..."
	python3 ../scripts/build-ksi-signal.py
	@echo "✅ ksi-signal.json built (local only)"

# Build the OSCAL Rev 5 SSP from the canonical inventory and the FedRAMP KSI
# catalog. Writes a local file; publishes nothing.
build-oscal-ssp:
	@echo "Building OSCAL Rev 5 SSP..."
	python3 ../scripts/build-oscal-ssp.py
	@echo "✅ oscal-ssp.json built (local only)"


# Run compliance check
check-compliance:
	@echo "Running compliance check..."
	@LAMBDA_FUNCTION=$$(terraform output -raw lambda_function_name 2>/dev/null) || { \
		echo "❌ Could not get Lambda function name. Deploy infrastructure first."; \
		exit 1; \
	}; \
	aws lambda invoke \
		--function-name $$LAMBDA_FUNCTION \
		--payload '{}' \
		compliance-result.json && \
	echo "Compliance check results:" && \
	cat compliance-result.json | jq '.'

# Create SSL certificate
create-cert:
	@echo "Creating SSL certificate for $(DOMAIN_NAME)..."
	aws acm request-certificate \
		--domain-name $(DOMAIN_NAME) \
		--subject-alternative-names "*.$(DOMAIN_NAME)" \
		--validation-method DNS \
		--region us-east-1
	@echo "Certificate requested. Complete DNS validation in ACM console."
	@echo "Then update terraform.tfvars with the certificate ARN."

# Validate terraform files
validate:
	@echo "Validating Terraform configuration..."
	terraform validate
	@echo "Validating OPA policies..."
	opa fmt --list policy/
	opa test policy/
	@echo "✅ Validation complete"

# Show outputs
outputs:
	@echo "Terraform outputs:"
	@terraform output -json | jq '.'

# Show current state
status:
	@echo "Current infrastructure status:"
	@echo "Region: $$(terraform output -raw aws_region 2>/dev/null || echo 'Not deployed')"
	@echo "S3 Bucket: $$(terraform output -raw s3_bucket_name 2>/dev/null || echo 'Not deployed')"
	@echo "CloudFront Distribution: $$(terraform output -raw cloudfront_distribution_id 2>/dev/null || echo 'Not deployed')"
	@echo "Website URLs:"
	@terraform output -json website_urls 2>/dev/null | jq -r 'to_entries[] | "  \(.key): \(.value // "Not deployed")"' || echo "  Not deployed"

# Destroy infrastructure
destroy:
	@echo "⚠️  This will destroy ALL infrastructure for $(DOMAIN_NAME)"
	@read -p "Are you sure? (type 'yes' to confirm): " confirm && [ "$$confirm" = "yes" ] || exit 1
	terraform destroy -auto-approve
	@echo "✅ Infrastructure destroyed"

# Clean temporary files
clean:
	@echo "Cleaning temporary files..."
	rm -f tfplan tfplan.json opa-input.json resource-input.json opa-result.json compliance-result.json
	rm -f validations.json validations.ndjson ksi-signal.json ksi-signal.bundle oscal-ssp.json
	rm -f opa-compliance.zip lambda/policy.wasm
	@echo "✅ Cleanup complete"

# Development helpers
dev-setup: init
	@echo "Setting up development environment..."
	@if [ ! -f terraform.tfvars ]; then \
		cp terraform.tfvars.example terraform.tfvars; \
		echo "📝 Created terraform.tfvars from example. Please customize it."; \
	fi
	@echo "✅ Development setup complete"

# Inventory gate: validate an already-built ksi-signal.json (PURL validity,
# native_id uniqueness, ecosystem-faithful typing). Blocks the deploy in CI.
gate:
	@echo "Running KSI inventory gate..."
	python3 ../scripts/validate-ksi-signal.py ksi-signal.json
	@echo "✅ Inventory gate passed"

# Python unit/integration tests (inventory gate, provenance, PURLs, SSP params,
# CMMC mapping, figure injection). Runnable in PR CI without AWS state.
python-test:
	@echo "Running Python test suite..."
	cd .. && python3 -m pytest tests/ -q

# Reconciliation gate (assessment keystone): fails closed if any cross-artifact
# invariant breaks (completeness, referential, suppressions, impact level,
# inventory binding, publish freshness). Run from infrastructure/ after the
# signal/SSP/POA&M/VDR are built. RECONCILE_FLAGS="--live" enumerates live AWS
# for the completeness invariant in CI.
reconcile:
	@echo "Running reconciliation gate..."
	cd .. && python3 scripts/reconcile.py --artifacts-dir infrastructure $(RECONCILE_FLAGS)

# Independent verification: fetch the LIVE published evidence and reproduce the
# verdict from the public internet — cosign signature/provenance (Sigstore +
# pinned identity), the dependency-free claims check, and the AWS-free
# cross-artifact reconciliation. Needs no secrets and no AWS. Override the base
# with VERIFY_BASE=https://host/.well-known.
verify-published:
	cd .. && scripts/verify-published.sh $(VERIFY_BASE)

# Figure freshness gate: every <span data-figure> in the paper and dashboard
# must match the value recomputed from the canonical artifacts. Fails if a
# committed figure has drifted from its source. Runnable without AWS state.
figures-check:
	@echo "Checking single-source figures..."
	cd .. && python3 scripts/inject-figures.py --check

# Test OPA policies locally (unit tests + coverage floor + one live example)
test-policies:
	@echo "Testing OPA policies..."
	opa test --coverage --threshold 90 policy/ > /dev/null
	opa test policy/
	@echo '{"resource":{"type":"aws_s3_bucket","name":"test-bucket","tags":{}}}' > test-input.json
	opa eval --strict-builtin-errors -d policy/ -i test-input.json "data.terraform.compliance.compliance_report"
	@rm -f test-input.json
	@echo "✅ Policy test complete"

# Scan ../website for WCAG 2 AA errors locally — the same scanner + policy
# the CI gate runs, so new content fails at your desk instead of in CI.
# One-time setup: (cd ../tools/a11y && npm ci --ignore-scripts). If browser
# autodetection misses, set A11Y_CHROME=/path/to/chromium; in container/root
# environments set A11Y_NO_SANDBOX=1.
a11y:
	@echo "Scanning ../website with pa11y (WCAG 2 AA)..."
	cd .. && node tools/a11y/scan.js website --out a11y-scan.json && \
	jq -n --arg now "$$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{runtime: {evaluated_at: $$now}}' > eval-context.json && \
	opa eval --strict-builtin-errors -d infrastructure/policy -d eval-context.json \
		-i a11y-scan.json "data.terraform.compliance.compliance_report" > a11y-report.json && \
	jq '.result[0].expressions[0].value | {compliant, violations: [.violations[] | {resource, code}], excepted: [.excepted[] | {resource: .violation.resource, ticket: .exception.ticket}]}' a11y-report.json && \
	COMPLIANT=$$(jq -r '.result[0].expressions[0].value.compliant' a11y-report.json); \
	rm -f a11y-scan.json a11y-report.json eval-context.json; \
	if [ "$$COMPLIANT" = "true" ]; then echo "✅ Accessibility gate green"; else echo "❌ Accessibility violations found"; exit 1; fi

# Format code
fmt:
	@echo "Formatting code..."
	terraform fmt -recursive
	opa fmt --write policy/
	@echo "✅ Code formatted"

# Security scan
security-scan:
	@echo "Running security scans..."
	@if command -v tfsec >/dev/null 2>&1; then \
		echo "Running tfsec..."; \
		tfsec .; \
	else \
		echo "tfsec not installed. Install with: go install github.com/aquasecurity/tfsec/cmd/tfsec@latest"; \
	fi
	@if command -v checkov >/dev/null 2>&1; then \
		echo "Running checkov..."; \
		checkov -f main.tf; \
	else \
		echo "checkov not installed. Install with: pip install checkov"; \
	fi
	@echo "✅ Security scan complete"

# Local infrastructure pipeline: set up, validate, plan, apply. Stops there.
#
# This is NOT the full compliance pipeline and never was — it does not build the
# POA&M, VDR, IIW, SCuBA bundle, SDR, CPO or CDS artifacts, does not sign
# anything with cosign, and does not run the reconciliation gate. That whole
# sequence is .github/workflows/deploy-with-opa.yml. Run `make reconcile` and
# `make gate` locally for the offline half.
pipeline: dev-setup validate plan apply-infra
