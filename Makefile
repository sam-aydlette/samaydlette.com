# Makefile for Website Deployment with OPA Compliance

.PHONY: help init plan deploy destroy check-compliance sync-content clean

# Default target
help:
	@echo "Available targets:"
	@echo "  init             - Initialize Terraform and install dependencies"
	@echo "  plan             - Run Terraform plan with OPA compliance check"
	@echo "  deploy           - Deploy infrastructure and sync website content"
	@echo "  sync-content     - Sync website files to S3"
	@echo "  check-compliance - Run post-deployment compliance check"
	@echo "  destroy          - Destroy all infrastructure"
	@echo "  clean            - Clean temporary files"
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
		curl -L -o opa https://openpolicyagent.org/downloads/v0.57.0/opa_linux_amd64_static; \
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

# Deploy infrastructure
deploy:
	@echo "Deploying infrastructure..."
	@if [ ! -f tfplan ]; then \
		echo "❌ No Terraform plan found. Run 'make plan' first."; \
		exit 1; \
	fi
	terraform apply tfplan
	@$(MAKE) sync-content
	@$(MAKE) check-compliance
	@echo "✅ Deployment complete!"
	@echo "Website URL: $$(terraform output -raw website_urls | jq -r '.domain // .cloudfront')"

# Sync website content to S3
sync-content:
	@echo "Syncing website content..."
	@BUCKET_NAME=$$(terraform output -raw s3_bucket_name 2>/dev/null) || { \
		echo "❌ Could not get S3 bucket name. Deploy infrastructure first."; \
		exit 1; \
	}; \
	aws s3 sync . s3://$$BUCKET_NAME/ \
		--exclude "*.tf" \
		--exclude "*.tfvars*" \
		--exclude "*.tfstate*" \
		--exclude ".terraform/*" \
		--exclude "lambda/*" \
		--exclude "*.sh" \
		--exclude "*.rego" \
		--exclude "*.json" \
		--exclude ".git/*" \
		--exclude "README.md" \
		--exclude "Makefile" \
		--exclude ".gitignore" \
		--delete
	@echo "Invalidating CloudFront cache..."
	@DISTRIBUTION_ID=$$(terraform output -raw cloudfront_distribution_id 2>/dev/null) || { \
		echo "Warning: Could not get CloudFront distribution ID"; \
		exit 0; \
	}; \
	aws cloudfront create-invalidation --distribution-id $$DISTRIBUTION_ID --paths "/*"
	@echo "✅ Content sync complete"

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
	opa fmt --list policies.rego
	opa test policies.rego
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
	rm -f lambda/policies.rego
	rm -f opa-compliance.zip
	@echo "✅ Cleanup complete"

# Development helpers
dev-setup: init
	@echo "Setting up development environment..."
	@if [ ! -f terraform.tfvars ]; then \
		cp terraform.tfvars.example terraform.tfvars; \
		echo "📝 Created terraform.tfvars from example. Please customize it."; \
	fi
	@echo "✅ Development setup complete"

# Test OPA policies locally
test-policies:
	@echo "Testing OPA policies..."
	@echo '{"resource":{"type":"aws_s3_bucket","name":"test-bucket","tags":{}}}' > test-input.json
	opa eval -d policies.rego -i test-input.json "data.terraform.compliance.compliance_report"
	@rm -f test-input.json
	@echo "✅ Policy test complete"

# Format code
fmt:
	@echo "Formatting code..."
	terraform fmt -recursive
	opa fmt --write policies.rego
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

# Full deployment pipeline
pipeline: dev-setup validate plan deploy
