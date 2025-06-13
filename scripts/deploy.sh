#!/bin/bash
# deploy.sh - Complete deployment script with OPA compliance

set -e

echo "=== Website Deployment with OPA Compliance ==="
echo "Domain: ${DOMAIN_NAME:-samaydlette.com}"
echo "Environment: ${ENVIRONMENT:-prod}"
echo

# Function to check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        echo "Error: AWS CLI is not installed."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        echo "Error: AWS credentials not configured."
        echo "Run: aws configure"
        exit 1
    fi
    
    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        echo "Error: Terraform is not installed."
        exit 1
    fi
    
    # Check OPA
    if ! command -v opa &> /dev/null; then
        echo "Installing OPA..."
        curl -L -o opa https://openpolicyagent.org/downloads/v0.57.0/opa_linux_amd64_static
        chmod 755 ./opa
        sudo mv opa /usr/local/bin
        echo "OPA installed successfully."
    fi
    
    # Check if terraform.tfvars exists
    if [ ! -f "terraform.tfvars" ]; then
        echo "Error: terraform.tfvars not found."
        echo "Copy terraform.tfvars.example to terraform.tfvars and customize it."
        exit 1
    fi
    
    echo "✅ Prerequisites check passed"
}

# Function to prepare Lambda package
prepare_lambda() {
    echo "Preparing Lambda function..."
    
    cd lambda
    
    # Install dependencies
    if [ -f "package.json" ]; then
        echo "Installing Node.js dependencies..."
        npm install --production
    fi
    
    # Copy policies to lambda directory
    cp ../policies.rego .
    
    cd ..
    
    echo "✅ Lambda function prepared"
}

# Function to create SSL certificate if needed
setup_ssl_certificate() {
    local domain_name=$1
    
    echo "Checking SSL certificate configuration..."
    
    # Check if we should create a certificate
    if grep -q "create_certificate.*=.*true" terraform.tfvars; then
        echo "✅ Certificate will be auto-created in us-east-1"
        return 0
    fi
    
    # Check if certificate ARN is provided
    if grep -q "ssl_certificate_arn.*=.*arn:aws:acm" terraform.tfvars; then
        echo "✅ SSL certificate ARN found in terraform.tfvars"
        return 0
    fi
    
    echo "SSL certificate configuration incomplete."
    echo "Choose an option:"
    echo "1. Auto-create certificate (recommended)"
    echo "2. Provide existing certificate ARN"
    read -p "Enter choice (1 or 2): " choice
    
    case $choice in
        1)
            sed -i 's/create_certificate = false/create_certificate = true/' terraform.tfvars
            echo "✅ Configured to auto-create certificate"
            ;;
        2)
            echo "Please manually add your certificate ARN to terraform.tfvars"
            echo "Certificate must be in us-east-1 region for CloudFront"
            exit 1
            ;;
        *)
            echo "Invalid choice"
            exit 1
            ;;
    esac
}

# Function to sync website files
sync_website_files() {
    local bucket_name=$1
    
    echo "Syncing website files to S3..."
    
    # Check if website files exist
    if [ ! -f "index.html" ]; then
        echo "Warning: index.html not found in current directory"
        echo "Make sure you're running this from your website root directory"
    fi
    
    # Sync files to S3
    aws s3 sync . s3://"$bucket_name"/ \
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
        --delete
    
    echo "✅ Website files synced"
}

# Function to run compliance check
run_compliance_check() {
    echo "Running post-deployment compliance check..."
    
    # Get Lambda function name from Terraform output
    local lambda_function=$(terraform output -raw lambda_function_name 2>/dev/null || echo "")
    
    if [ -n "$lambda_function" ]; then
        echo "Invoking compliance check Lambda function..."
        aws lambda invoke \
            --function-name "$lambda_function" \
            --payload '{}' \
            compliance-result.json
        
        echo "Compliance check results:"
        cat compliance-result.json | jq '.'
        
        # Check if compliant
        local compliant=$(cat compliance-result.json | jq -r '.body' | jq -r '.compliant // false')
        if [ "$compliant" = "true" ]; then
            echo "✅ Post-deployment compliance check passed"
        else
            echo "❌ Post-deployment compliance violations found"
            echo "Check the compliance report for details"
        fi
    else
        echo "Warning: Could not find Lambda function for compliance check"
    fi
}

# Function to invalidate CloudFront cache
invalidate_cloudfront() {
    echo "Invalidating CloudFront cache..."
    
    local distribution_id=$(terraform output -raw cloudfront_distribution_id 2>/dev/null || echo "")
    
    if [ -n "$distribution_id" ]; then
        aws cloudfront create-invalidation \
            --distribution-id "$distribution_id" \
            --paths "/*"
        echo "✅ CloudFront cache invalidated"
    else
        echo "Warning: Could not find CloudFront distribution ID"
    fi
}

# Main deployment flow
main() {
    local domain_name=${DOMAIN_NAME:-samaydlette.com}
    
    check_prerequisites
    setup_ssl_certificate "$domain_name"
    prepare_lambda
    
    echo "Running Terraform plan with OPA compliance check..."
    bash terraform-plan.sh
    
    echo
    read -p "Deploy the infrastructure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deploying infrastructure..."
        terraform apply tfplan
        
        # Get bucket name from output
        local bucket_name=$(terraform output -raw s3_bucket_name)
        
        sync_website_files "$bucket_name"
        invalidate_cloudfront
        run_compliance_check
        
        echo
        echo "=== Deployment Complete ==="
        echo "Website URL: $(terraform output -json website_urls | jq -r '.domain // .cloudfront')"
        echo "S3 Bucket: $bucket_name"
        echo "CloudFront Distribution: $(terraform output -raw cloudfront_distribution_id)"
        
        if terraform output route53_name_servers &> /dev/null; then
            echo
            echo "DNS Configuration:"
            echo "Update your domain registrar to use these name servers:"
            terraform output -json route53_name_servers | jq -r '.[]'
        fi
        
        echo
        echo "✅ Deployment successful!"
    else
        echo "Deployment cancelled."
    fi
}

# Cleanup function
cleanup() {
    echo "Cleaning up temporary files..."
    rm -f tfplan tfplan.json opa-input.json compliance-result.json
    rm -f lambda/policies.rego
}

# Set trap for cleanup
trap cleanup EXIT

# Run main function
