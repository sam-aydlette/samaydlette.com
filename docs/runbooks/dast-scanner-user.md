# DAST scanner user (authenticated ZAP API scan)

The authenticated ZAP API scan of the Silk Reeling API
(`.github/workflows/zap-dast.yml`, job `zap_api`) signs in as a dedicated
Cognito user in the Silk Reeling user pool. The user, like every user of that
pool, is created by the operator (the pool allows admin-created users only) and
must use TOTP MFA (the pool requires it). The workflow signs in with SRP and a
TOTP code (`scripts/dast-cognito-token.py`), the flows the SPA's app client
already allows; no app-client setting changes for it.

Four repository secrets carry what the sign-in needs:

| Secret | Value |
|---|---|
| `SILK_DAST_USERNAME` | the scanner user's username (an email-form name; no mailbox is needed) |
| `SILK_DAST_PASSWORD` | its password |
| `SILK_DAST_TOTP_SECRET` | its TOTP seed, from the one-time enrolment below |
| `SILK_DAST_USER_POOL_ID` | the Silk Reeling user pool id (SRP signs with it) |

The deploy fails before `terraform apply` if any of them is missing (step
"Require the DAST scanner credentials"); the scan fails without them, and 72
hours later so does every VDR build (`detection.zap-api`).

## Create the user and the secrets (once)

Run from a checkout of `main`, with AWS credentials that can administer the
pool and a `gh` login that can set repository secrets. Nothing secret is
echoed: the password is generated into a shell variable and the TOTP seed goes
straight into its secret.

```bash
set -euo pipefail
export AWS_REGION=us-east-2
REPO=sam-aydlette/samaydlette.com
POOL=$(aws cognito-idp list-user-pools --max-results 60 \
  --query "UserPools[?Name=='samaydlette-com-silk-reeling-users'].Id | [0]" --output text)
SCANNER='zap-dast-scanner@samaydlette.com'   # any email-form name; no mail is sent to it
PW="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24) + "aA1!")')"

aws cognito-idp admin-create-user --user-pool-id "$POOL" --username "$SCANNER" \
  --user-attributes Name=email,Value="$SCANNER" Name=email_verified,Value=true \
  --message-action SUPPRESS > /dev/null
# The password goes in on stdin (printf is a shell builtin), never on a command line.
printf '{"UserPoolId":"%s","Username":"%s","Password":"%s","Permanent":true}' "$POOL" "$SCANNER" "$PW" \
  | aws cognito-idp admin-set-user-password --cli-input-json file:///dev/stdin

printf '%s' "$SCANNER" | gh secret set SILK_DAST_USERNAME -R "$REPO"
printf '%s' "$PW"      | gh secret set SILK_DAST_PASSWORD -R "$REPO"
printf '%s' "$POOL"    | gh secret set SILK_DAST_USER_POOL_ID -R "$REPO"

# TOTP enrolment: answers the MFA_SETUP challenge with a new authenticator seed
# (Cognito's public user APIs, no AWS credentials) and prints only that seed.
curl -sf https://samaydlette.com/.well-known/silk-reeling-auth.json > /tmp/silk-auth.json
SEED=$(SILK_DAST_USERNAME="$SCANNER" SILK_DAST_PASSWORD="$PW" SILK_DAST_USER_POOL_ID="$POOL" \
  python3 scripts/dast-cognito-token.py enroll --auth-config /tmp/silk-auth.json)
printf '%s' "$SEED" | gh secret set SILK_DAST_TOTP_SECRET -R "$REPO"

# Check: a full sign-in works (prints the token's length, not the token). The
# wait moves past the enrolment's TOTP window: Cognito refuses a reused code.
sleep 31
SILK_DAST_USERNAME="$SCANNER" SILK_DAST_PASSWORD="$PW" SILK_DAST_USER_POOL_ID="$POOL" \
  SILK_DAST_TOTP_SECRET="$SEED" \
  python3 scripts/dast-cognito-token.py token --auth-config /tmp/silk-auth.json | wc -c
unset PW SEED
```

## First deploy after the change that introduced this

The deploy and the nightly now require a successful ZAP run that includes the
API scan, and a CodeQL analysis of every category (`.github/workflows/codeql.yml`)
in the last 72 hours. After merging, before approving the deploy:

1. Let **CodeQL** finish on the merge commit (it runs on push to `main`).
2. Run **ZAP DAST Scan** from the Actions tab and let it pass.
3. Approve the deploy.

## Rotation and removal

- Password: generate a new value and set it as above (`admin-set-user-password`
  from stdin, `Permanent: true`), then update `SILK_DAST_PASSWORD`.
- TOTP seed: `aws cognito-idp admin-set-user-mfa-preference` cannot replace a
  seed; delete and recreate the user, then repeat the steps above.
- Disable the scanner without deleting it:
  `aws cognito-idp admin-disable-user --user-pool-id "$POOL" --username "$SCANNER"`
  (the next ZAP run then fails, which is the intended signal).
