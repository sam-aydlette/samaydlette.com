# =============================================================================
# CloudFront edge — managed here in the bootstrap (foundational) stack
# =============================================================================
# The distribution that serves the whole site (and proxies the Silk Reeling app)
# is foundational, rarely-changing infrastructure. It is managed here, in the
# manually-applied bootstrap stack with local state, for the same reasons the
# IAM trust layer is: it should change deliberately, not be re-applied on every
# website deploy. The per-deploy pipeline in ../ keeps READING it through
# `data "aws_cloudfront_distribution" "website"`, so a routine website deploy
# never plans or mutates the distribution.
#
# This configuration was reconciled byte-for-byte against the live distribution
# (terraform plan == "No changes") before being committed, including the
# custom_error_response entries that route 403/404 to the styled /404.html page.
#
# To bring it under management on a fresh bootstrap state:
#   terraform import aws_cloudfront_origin_access_control.website <OAC_ID>
#   terraform import aws_cloudfront_distribution.website          <DISTRIBUTION_ID>
# then `terraform plan` should report no changes.
# =============================================================================

# ACM certificate for the aliases (must be in us-east-1 for CloudFront).
data "aws_acm_certificate" "website" {
  provider    = aws.us_east_1
  domain      = var.domain_name
  statuses    = ["ISSUED"]
  most_recent = true
}

# AWS-managed cache / origin-request policies used by the /silk-reeling/* behavior.
# These are well-known global managed policies (same IDs in every account); read
# by name so no magic IDs are hard-coded.
data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

# The viewer-request function that strips the /silk-reeling prefix before the
# request reaches the API Gateway origin. Referenced (not managed) here so its
# code is not duplicated; it is published out-of-band from
# ../cloudfront/silk-reeling-strip-prefix.js.
data "aws_cloudfront_function" "strip_prefix" {
  name  = "silk-reeling-strip-prefix"
  stage = "LIVE"
}

# Origin Access Control: lets CloudFront (and only CloudFront) read the private
# S3 origin via SigV4. Managed here; the S3 bucket policy in ../ already trusts
# the distribution ARN.
resource "aws_cloudfront_origin_access_control" "website" {
  name                              = "${var.domain_name}-oac"
  description                       = "OAC for ${var.domain_name}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Security headers delivered at the edge to the static site: HSTS, X-Frame-Options,
# X-Content-Type-Options, Referrer-Policy, X-XSS-Protection, and an enforcing
# Content-Security-Policy. The CSP was rolled out report-only first and verified
# clean (headless, no violations across the dynamic pages) before enforcing; its
# frame-src allows the YouTube and libsyn (activities.html podcast) embeds.
# Attached to the default (static-site) behavior only; the /silk-reeling/*
# application path is left off this policy.
resource "aws_cloudfront_response_headers_policy" "website" {
  name    = "${replace(var.domain_name, ".", "-")}-security-headers"
  comment = "Baseline security headers for ${var.domain_name}"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    content_security_policy {
      content_security_policy = join("; ", [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "media-src 'self' https://ochelli.com",
        "frame-src https://www.youtube.com https://www.youtube-nocookie.com https://html5-player.libsyn.com",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
      ])
      override = true
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }
}

resource "aws_cloudfront_distribution" "website" {
  # Scanner findings that describe this distribution's deliberate posture, each
  # classified here at scan-time (not silently dropped) and tracked in the POA&M
  # register. (CKV2_AWS_32, response-headers policy, is now resolved — a policy is
  # attached to the default behavior below — so its skip is removed; POAM-031 closed.)
  # checkov:skip=CKV_AWS_310:Risk-accepted (POAM-009). The two origins serve distinct path patterns (static S3 site vs the Silk Reeling API), not a redundant failover pair, so an origin group does not apply.
  # checkov:skip=CKV2_AWS_47:Risk-accepted (POAM-007/008). A WAF is intentionally declined for this system (SC-7/SC-5 met via the CloudFront + API Gateway managed interfaces, Shield Standard, and throttling); there is also no Java/Log4j runtime in scope, so the Log4j AMR rule is moot.
  # checkov:skip=CKV_AWS_374:Not applicable. This is a public personal website intended to be reachable from every geography; no control requires geo-blocking. Documented as a false positive for this system.
  enabled             = true
  is_ipv6_enabled     = true
  comment             = ""
  default_root_object = "index.html"
  http_version        = "http2"
  price_class         = "PriceClass_100"
  aliases             = ["www.${var.domain_name}", var.domain_name]

  # Private S3 origin (static site), reached through the OAC above.
  origin {
    origin_id                = "S3-${var.domain_name}"
    domain_name              = "${var.domain_name}.s3.${var.aws_region}.amazonaws.com"
    origin_access_control_id = aws_cloudfront_origin_access_control.website.id
    connection_attempts      = 3
    connection_timeout       = 10
  }

  # Silk Reeling API Gateway origin (the app behind /silk-reeling/*).
  origin {
    origin_id           = "apigw-silk-reeling"
    domain_name         = var.silk_reeling_api_origin_domain
    connection_attempts = 3
    connection_timeout  = 10
    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 30
      origin_keepalive_timeout = 5
    }
  }

  # Static site: cache normally, redirect to HTTPS, and add the security headers
  # (HSTS, CSP, frame/content-type/referrer/XSS) at the edge.
  default_cache_behavior {
    target_origin_id           = "S3-${var.domain_name}"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.website.id
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods        = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods         = ["HEAD", "GET"]
    compress               = true
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  # App path: no caching, forward everything except Host (so the JWT authorizer
  # sees the Authorization header), strip the prefix at the edge.
  ordered_cache_behavior {
    path_pattern             = "/silk-reeling/*"
    target_origin_id         = "apigw-silk-reeling"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods           = ["HEAD", "GET"]
    compress                 = true
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    function_association {
      event_type   = "viewer-request"
      function_arn = data.aws_cloudfront_function.strip_prefix.arn
    }
  }

  # Serve the styled 404 page. S3-via-OAC returns 403 for a missing object, so
  # both 403 and 404 map to /404.html with a real 404 status. Short error cache
  # so a fixed/added page propagates quickly.
  custom_error_response {
    error_code            = 403
    response_code         = 404
    response_page_path    = "/404.html"
    error_caching_min_ttl = 10
  }
  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = "/404.html"
    error_caching_min_ttl = 10
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = data.aws_acm_certificate.website.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = {
    Name               = "${var.domain_name}-cdn"
    Environment        = var.deploy_environment
    Owner              = var.owner_email
    CostCenter         = "website-ops"
    DataClassification = "Public"
    ComplianceScope    = "Section508"
  }

  # The distribution serves the entire site and the app. It must never be
  # replaced or destroyed by a plan; changes are made in place and reviewed.
  lifecycle {
    prevent_destroy = true
  }
}

variable "silk_reeling_api_origin_domain" {
  type        = string
  description = "Hostname of the Silk Reeling API Gateway origin behind the /silk-reeling/* behavior, e.g. <api-id>.execute-api.<region>.amazonaws.com. Supplied at apply time; not a secret, but kept out of committed code so the stack stays portable."
}

variable "owner_email" {
  type        = string
  description = "Value for the distribution's Owner tag. Supplied at apply time so a personal address is not committed to the public repo."
}
