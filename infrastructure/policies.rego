# policies.rego - OPA Compliance Policies

package terraform.compliance

import rego.v1

# Required tags policy
required_tags := {
    "Environment",
    "CostCenter", 
    "DataClassification",
    "Owner"
}

# Check if all required tags are present
missing_required_tags contains tag if {
    some tag in required_tags
    not input.resource.tags[tag]
}

# S3 bucket compliance rules
s3_bucket_violations contains violation if {
    input.resource.type == "aws_s3_bucket"
    count(missing_required_tags) > 0
    violation := {
        "type": "missing_required_tags",
        "message": sprintf("S3 bucket missing required tags: %v", [missing_required_tags]),
        "severity": "HIGH",
        "resource": input.resource.name
    }
}

s3_bucket_violations contains violation if {
    input.resource.type == "aws_s3_bucket"
    not input.resource.versioning_enabled
    violation := {
        "type": "versioning_disabled", 
        "message": "S3 bucket versioning must be enabled for compliance",
        "severity": "MEDIUM",
        "resource": input.resource.name
    }
}

s3_bucket_violations contains violation if {
    input.resource.type == "aws_s3_bucket"
    not input.resource.encryption_enabled
    violation := {
        "type": "encryption_disabled",
        "message": "S3 bucket server-side encryption must be enabled",
        "severity": "HIGH", 
        "resource": input.resource.name
    }
}

# CloudFront compliance rules
cloudfront_violations contains violation if {
    input.resource.type == "aws_cloudfront_distribution"
    input.resource.viewer_protocol_policy != "redirect-to-https"
    violation := {
        "type": "insecure_protocol",
        "message": "CloudFront must redirect HTTP to HTTPS",
        "severity": "HIGH",
        "resource": input.resource.name
    }
}

cloudfront_violations contains violation if {
    input.resource.type == "aws_cloudfront_distribution"
    input.resource.minimum_protocol_version != "TLSv1.2_2021"
    violation := {
        "type": "weak_tls",
        "message": "CloudFront must use TLS 1.2 or higher",
        "severity": "MEDIUM",
        "resource": input.resource.name
    }
}

# Section 508 compliance rules for web content
section_508_violations contains violation if {
    input.html_content
    not has_alt_attributes(input.html_content)
    violation := {
        "type": "missing_alt_text",
        "message": "Images must have alt attributes for Section 508 compliance",
        "severity": "HIGH",
        "standard": "Section 508 - 1194.22(a)"
    }
}

section_508_violations contains violation if {
    input.html_content
    not has_proper_headings(input.html_content)
    violation := {
        "type": "improper_heading_structure",
        "message": "Page must have proper heading structure (h1, h2, etc.)",
        "severity": "MEDIUM", 
        "standard": "Section 508 - 1194.22(g)"
    }
}

section_508_violations contains violation if {
    input.html_content
    not has_lang_attribute(input.html_content)
    violation := {
        "type": "missing_lang_attribute",
        "message": "HTML element must have lang attribute",
        "severity": "MEDIUM",
        "standard": "Section 508 - 1194.22(q)"
    }
}

section_508_violations contains violation if {
    input.html_content
    has_color_only_information(input.html_content)
    violation := {
        "type": "color_only_information",
        "message": "Information cannot be conveyed by color alone",
        "severity": "HIGH",
        "standard": "Section 508 - 1194.22(c)"
    }
}

# Helper functions for HTML analysis
has_alt_attributes(html) if {
    # Check if all img tags have alt attributes
    images := regex.find_n(`<img[^>]*>`, html, -1)
    count(images) > 0
    all_have_alt := [img | 
        img := images[_]
        contains(img, "alt=")
    ]
    count(all_have_alt) == count(images)
}

has_alt_attributes(html) if {
    # No images found - compliance by default
    images := regex.find_n(`<img[^>]*>`, html, -1)
    count(images) == 0
}

has_proper_headings(html) if {
    # Check for at least one h1 tag
    h1_tags := regex.find_n(`<h1[^>]*>`, html, -1)
    count(h1_tags) >= 1
}

has_lang_attribute(html) if {
    # Check if html tag has lang attribute
    html_tags := regex.find_n(`<html[^>]*lang=`, html, -1)
    count(html_tags) > 0
}

has_color_only_information(html) if {
    # Simple check for common color-only patterns
    # This is a basic implementation - real-world would be more sophisticated
    color_patterns := [
        "color: red",
        "color: green", 
        "style=\"color:",
        "class=\"red\"",
        "class=\"green\""
    ]
    
    some pattern in color_patterns
    contains(html, pattern)
    
    # Check if there's also non-color indication (like icons, text)
    accessibility_indicators := [
        "class=\"icon\"",
        "aria-label=",
        "title=",
        "❌", "✅", "⚠️"  # Common accessibility emoji
    ]
    
    not some indicator in accessibility_indicators
    contains(html, indicator)
}

# Main compliance evaluation
default compliant := true

compliant := false if {
    count(s3_bucket_violations) > 0
}

compliant := false if {
    count(cloudfront_violations) > 0
}

compliant := false if {
    count(section_508_violations) > 0
}

# Collect all violations
all_violations := array.concat(
    array.concat(s3_bucket_violations, cloudfront_violations),
    section_508_violations
)

# Summary report
compliance_report := {
    "compliant": compliant,
    "total_violations": count(all_violations),
    "violations_by_severity": {
        "HIGH": count([v | v := all_violations[_]; v.severity == "HIGH"]),
        "MEDIUM": count([v | v := all_violations[_]; v.severity == "MEDIUM"]),
        "LOW": count([v | v := all_violations[_]; v.severity == "LOW"])
    },
    "violations": all_violations,
    "timestamp": time.now_ns(),
    "policy_version": "1.0"
