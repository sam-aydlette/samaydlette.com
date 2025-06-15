# policies.rego - Simple OPA Compliance Policies

package terraform.compliance

# Required tags policy
required_tags := {
    "Environment",
    "CostCenter", 
    "DataClassification",
    "Owner"
}

# Check if all required tags are present
missing_required_tags[tag] {
    tag := required_tags[_]
    not input.resource.tags[tag]
}

# S3 bucket compliance rules
s3_bucket_violations[violation] {
    input.resource.type == "aws_s3_bucket"
    count(missing_required_tags) > 0
    violation := {
        "type": "missing_required_tags",
        "message": sprintf("S3 bucket missing required tags: %v", [missing_required_tags]),
        "severity": "HIGH",
        "resource": input.resource.name
    }
}

s3_bucket_violations[violation] {
    input.resource.type == "aws_s3_bucket"
    not input.resource.versioning_enabled
    violation := {
        "type": "versioning_disabled", 
        "message": "S3 bucket versioning must be enabled for compliance",
        "severity": "MEDIUM",
        "resource": input.resource.name
    }
}

s3_bucket_violations[violation] {
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
cloudfront_violations[violation] {
    input.resource.type == "aws_cloudfront_distribution"
    input.resource.viewer_protocol_policy != "redirect-to-https"
    violation := {
        "type": "insecure_protocol",
        "message": "CloudFront must redirect HTTP to HTTPS",
        "severity": "HIGH",
        "resource": input.resource.name
    }
}

cloudfront_violations[violation] {
    input.resource.type == "aws_cloudfront_distribution"
    input.resource.minimum_protocol_version != "TLSv1.2_2021"
    violation := {
        "type": "weak_tls",
        "message": "CloudFront must use TLS 1.2 or higher",
        "severity": "MEDIUM",
        "resource": input.resource.name
    }
}

# Main compliance evaluation
default compliant = true

compliant = false {
    count(s3_bucket_violations) > 0
}

compliant = false {
    count(cloudfront_violations) > 0
}

# Collect all violations (convert sets to arrays)
all_violations := s3_bucket_violations | cloudfront_violations

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
}