# =============================================================================
# OPA SECURITY POLICIES FOR TERRAFORM COMPLIANCE AND SECTION 508 ACCESSIBILITY
# =============================================================================
# This file contains the security rules that decide what infrastructure is
# allowed to be deployed AND whether website content meets accessibility standards.
# If any resource violates these rules, deployment is blocked.
#
# How this works:
# 1. Define what tags are required on all AWS resources
# 2. Check S3 buckets for proper security settings
# 3. Check CloudFront for secure configuration
# 4. Check HTML content for Section 508 accessibility compliance
# 5. Generate a final pass/fail report for deployment
# =============================================================================

# Define which part of OPA this belongs to
package terraform.compliance

# =============================================================================
# REQUIRED TAGS FOR ALL AWS RESOURCES
# =============================================================================
# Every AWS resource must have these tags for proper governance and cost tracking
# =============================================================================

required_tags := {
    "Environment",      # dev, staging, prod - helps track what this is for
    "CostCenter",       # who pays for this resource
    "DataClassification", # public, internal, confidential - what kind of data
    "Owner"            # who is responsible for this resource
}

# =============================================================================
# CHECK FOR MISSING TAGS
# =============================================================================
# Find any required tags that are missing from a resource
# =============================================================================

# This rule finds tags that should be there but aren't
missing_required_tags[tag] {
    tag := required_tags[_]           # Look at each required tag
    not input.resource.tags[tag]      # Check if this tag is missing
}

# =============================================================================
# S3 BUCKET SECURITY VIOLATIONS
# =============================================================================
# Check S3 buckets for required security settings
# =============================================================================

# Flag S3 buckets that are missing required tags
s3_bucket_violations[violation] {
    input.resource.type == "aws_s3_bucket"    # Only check S3 buckets
    count(missing_required_tags) > 0          # Some required tags are missing
    violation := {
        "type": "missing_required_tags",
        "message": sprintf("S3 bucket missing required tags: %v", [missing_required_tags]),
        "severity": "HIGH",
        "resource": input.resource.name
    }
}

# Flag S3 buckets that don't have versioning turned on
s3_bucket_violations[violation] {
    input.resource.type == "aws_s3_bucket"    # Only check S3 buckets
    not input.resource.versioning_enabled     # Versioning is not enabled
    violation := {
        "type": "versioning_disabled", 
        "message": "S3 bucket versioning must be enabled for compliance",
        "severity": "MEDIUM",
        "resource": input.resource.name
    }
}

# Flag S3 buckets that don't have encryption turned on
s3_bucket_violations[violation] {
    input.resource.type == "aws_s3_bucket"    # Only check S3 buckets
    not input.resource.encryption_enabled     # Encryption is not enabled
    violation := {
        "type": "encryption_disabled",
        "message": "S3 bucket server-side encryption must be enabled",
        "severity": "HIGH", 
        "resource": input.resource.name
    }
}

# =============================================================================
# CLOUDFRONT SECURITY VIOLATIONS
# =============================================================================
# Check CloudFront distributions for secure configuration
# =============================================================================

# Flag CloudFront that allows insecure HTTP connections
cloudfront_violations[violation] {
    input.resource.type == "aws_cloudfront_distribution"    # Only check CloudFront
    input.resource.viewer_protocol_policy != "redirect-to-https"    # Not forcing HTTPS
    violation := {
        "type": "insecure_protocol",
        "message": "CloudFront must redirect HTTP to HTTPS",
        "severity": "HIGH",
        "resource": input.resource.name
    }
}

# Flag CloudFront using old/weak encryption
cloudfront_violations[violation] {
    input.resource.type == "aws_cloudfront_distribution"    # Only check CloudFront
    input.resource.minimum_protocol_version != "TLSv1.2_2021"    # Using old encryption
    violation := {
        "type": "weak_tls",
        "message": "CloudFront must use TLS 1.2 or higher",
        "severity": "MEDIUM",
        "resource": input.resource.name
    }
}

# =============================================================================
# SECTION 508 ACCESSIBILITY VIOLATIONS
# =============================================================================
# Check HTML content for accessibility compliance
# =============================================================================

# Flag HTML files that don't have a language declaration
accessibility_violations[violation] {
    input.html_content != ""                              # Only check when HTML content exists
    input.file_name != ""                                 # And we have a filename
    not contains(input.html_content, "html lang=")        # Missing lang attribute
    violation := {
        "type": "missing_language_declaration",
        "message": sprintf("HTML file %s missing language declaration (html lang attribute)", [input.file_name]),
        "severity": "HIGH",
        "resource": input.file_name
    }
}

# Flag HTML files that have images without alt text
accessibility_violations[violation] {
    input.html_content != ""                              # Only check when HTML content exists
    input.file_name != ""                                 # And we have a filename
    contains(input.html_content, "<img")                  # Contains images
    img_without_alt := regex.find_all_string_submatch_n(
        `<img[^>]*(?:(?!alt=)[^>])*>`, 
        input.html_content, -1
    )
    count(img_without_alt) > 0                            # Found images without alt text
    violation := {
        "type": "missing_alt_text",
        "message": sprintf("HTML file %s contains images without alt text", [input.file_name]),
        "severity": "HIGH",
        "resource": input.file_name
    }
}

# Flag HTML files that don't have proper heading structure
accessibility_violations[violation] {
    input.html_content != ""                              # Only check when HTML content exists
    input.file_name != ""                                 # And we have a filename
    not contains(input.html_content, "<h1")               # No H1 heading found
    violation := {
        "type": "missing_main_heading",
        "message": sprintf("HTML file %s missing main heading (h1 element)", [input.file_name]),
        "severity": "MEDIUM",
        "resource": input.file_name
    }
}

# Flag HTML files that have empty alt attributes (alt="" with no text)
accessibility_violations[violation] {
    input.html_content != ""                              # Only check when HTML content exists
    input.file_name != ""                                 # And we have a filename
    contains(input.html_content, `alt=""`)                # Contains empty alt attributes
    not contains(input.html_content, "decorative")        # Unless marked as decorative
    violation := {
        "type": "empty_alt_text",
        "message": sprintf("HTML file %s contains images with empty alt text", [input.file_name]),
        "severity": "MEDIUM",
        "resource": input.file_name
    }
}

# Flag HTML files missing proper document structure
accessibility_violations[violation] {
    input.html_content != ""                              # Only check when HTML content exists
    input.file_name != ""                                 # And we have a filename
    not contains(input.html_content, "<!DOCTYPE html>")   # Missing DOCTYPE declaration
    violation := {
        "type": "missing_doctype",
        "message": sprintf("HTML file %s missing DOCTYPE declaration", [input.file_name]),
        "severity": "LOW",
        "resource": input.file_name
    }
}

# =============================================================================
# OVERALL COMPLIANCE DECISION
# =============================================================================
# Decide whether deployment should be allowed or blocked
# =============================================================================

# Start by assuming everything is compliant
default compliant = true

# Block deployment if any S3 bucket has violations
compliant = false {
    count(s3_bucket_violations) > 0
}

# Block deployment if any CloudFront has violations
compliant = false {
    count(cloudfront_violations) > 0
}

# Block deployment if any accessibility violations are found
compliant = false {
    count(accessibility_violations) > 0
}

# =============================================================================
# COLLECT ALL VIOLATIONS
# =============================================================================
# Gather all the problems found across all resources and content
# =============================================================================

# Combine all violations from infrastructure and accessibility checks
all_violations := s3_bucket_violations | cloudfront_violations | accessibility_violations

# =============================================================================
# GENERATE FINAL COMPLIANCE REPORT
# =============================================================================
# Create a summary report showing what was checked and what was found
# =============================================================================

compliance_report := {
    "compliant": compliant,                              # Overall pass/fail
    "total_violations": count(all_violations),           # How many problems found
    "violations_by_severity": {                          # Break down by severity
        "HIGH": count([v | v := all_violations[_]; v.severity == "HIGH"]),
        "MEDIUM": count([v | v := all_violations[_]; v.severity == "MEDIUM"]),
        "LOW": count([v | v := all_violations[_]; v.severity == "LOW"])
    },
    "violations_by_type": {                              # Break down by category
        "infrastructure": count(s3_bucket_violations | cloudfront_violations),
        "accessibility": count(accessibility_violations)
    },
    "violations": all_violations,                        # List of all problems
    "timestamp": time.now_ns(),                         # When this check ran
    "policy_version": "1.0"                             # Version of these rules
}