# =============================================================================
# Remote Terraform backend (Task 16, Phase C cutover)
# =============================================================================
# The per-deploy stack now persists state in S3 (bucket + lock provisioned in
# infrastructure/bootstrap/tf-state-backend.tf, Phase A) instead of rebuilding
# it by `terraform import` on every run.
#
# Migration is automatic: the first deploy after this merges runs against an
# empty remote state, so the existing (idempotent, state-show-guarded) import
# steps populate it once; from the next deploy on those imports find every
# resource already in state and skip, removing ~8.5 min/run. The reconciliation
# gate (reconcile.py --live) still verifies live AWS == inventory, so persisted
# state does not weaken drift detection.
#
# Phase C-2 (a follow-up) removes the now-redundant import steps entirely.
terraform {
  backend "s3" {
    bucket         = "samaydlette-com-tfstate"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "samaydlette-com-tflock"
    encrypt        = true
  }
}
