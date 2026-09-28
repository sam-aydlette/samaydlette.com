# =============================================================================
# Remote state for the bootstrap stack
# =============================================================================
# This stack used to keep local state on the operator's machine, which made the
# trust root invisible to CI: nothing could plan it for drift, and the canonical
# inventory silently omitted the identities it creates. Its state now lives
# beside the per-deploy stack's, under its own key, in the bucket and lock table
# this stack itself manages (both carry prevent_destroy or are guarded by it).
#
# CI READS this state and never writes it: the plan role plans the stack on every
# build and reports any pending change in the trust center; the deploy role reads
# it for the inventory. Applying it remains the operator's decision.
#
# One-time migration (operator, from a checkout synced to origin/main):
#   terraform init -migrate-state      # answer "yes" to copy local state to S3
#   terraform plan                     # must show no changes caused by the move
# Then delete the local terraform.tfstate* files.
terraform {
  backend "s3" {
    bucket         = "samaydlette-com-tfstate"
    key            = "bootstrap/terraform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "samaydlette-com-tflock"
    encrypt        = true
  }
}
