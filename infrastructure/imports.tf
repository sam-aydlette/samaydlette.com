# =============================================================================
# ONE-TIME ADOPTION OF EXISTING RESOURCES (import blocks, Terraform >= 1.5)
# =============================================================================
# Kept in their own file because tfsec (end of life) cannot parse import blocks;
# the Security Scan excludes this file only. Once a deploy has applied them they
# are no-ops; remove them (and this file) in a later change.
# =============================================================================

# One-time adoption of the existing records (Terraform >= 1.5). Once a deploy
# has applied these, they are no-ops and can be removed in a later change.
import {
  to = aws_route53_record.apex[0]
  id = "Z025777934PUN9NPN7X28_samaydlette.com_A"
}

import {
  to = aws_route53_record.www[0]
  id = "Z025777934PUN9NPN7X28_www.samaydlette.com_A"
}

import {
  to = aws_route53_record.acm_validation_apex[0]
  id = "Z025777934PUN9NPN7X28__b628b88de4ded9a53048bcfccc917493.samaydlette.com_CNAME"
}

import {
  to = aws_route53_record.acm_validation_www[0]
  id = "Z025777934PUN9NPN7X28__44dc48e27c8c30834255eeda9f2c8d63.www.samaydlette.com_CNAME"
}
