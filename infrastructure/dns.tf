# =============================================================================
# SITE DNS RECORDS
# =============================================================================
# The apex and www aliases to CloudFront and the two ACM validation CNAMEs were
# created by hand. The independent corroboration (RAMPART on TAP) observed them
# in Route 53 where no Terraform state described them, so a DNS change bypassed
# review and the boundary map could not draw the zone -> CloudFront connection.
# They are adopted here with import blocks; the configuration matches the live
# records exactly, so adoption changes nothing in DNS.
#
# The hosted zone itself stays a data source (main.tf): it predates this stack,
# its registrar delegation and DNSSEC chain hang off it, and nothing about it
# needs to change.
# =============================================================================

locals {
  site_zone_id = var.manage_dns ? data.aws_route53_zone.website[0].zone_id : null
}

resource "aws_route53_record" "apex" {
  count   = var.manage_dns ? 1 : 0
  zone_id = local.site_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = data.aws_cloudfront_distribution.website.domain_name
    zone_id                = data.aws_cloudfront_distribution.website.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "www" {
  count   = var.manage_dns ? 1 : 0
  zone_id = local.site_zone_id
  name    = "www.${var.domain_name}"
  type    = "A"

  alias {
    name                   = data.aws_cloudfront_distribution.website.domain_name
    zone_id                = data.aws_cloudfront_distribution.website.hosted_zone_id
    evaluate_target_health = false
  }
}

# ACM DNS validation for the certificate CloudFront serves. The certificate is
# read as a data source (main.tf), which does not expose its validation
# options, so the record values are stated; they are public DNS.
resource "aws_route53_record" "acm_validation_apex" {
  count   = var.manage_dns ? 1 : 0
  zone_id = local.site_zone_id
  name    = "_b628b88de4ded9a53048bcfccc917493.${var.domain_name}"
  type    = "CNAME"
  ttl     = 60
  records = ["_c259710eed1fa92a02bf116bbff40ecc.xlfgrmvvlj.acm-validations.aws."]
}

resource "aws_route53_record" "acm_validation_www" {
  count   = var.manage_dns ? 1 : 0
  zone_id = local.site_zone_id
  name    = "_44dc48e27c8c30834255eeda9f2c8d63.www.${var.domain_name}"
  type    = "CNAME"
  ttl     = 300
  records = ["_221481f32d19b544671f93cb344ff9cd.xlfgrmvvlj.acm-validations.aws."]
}

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
