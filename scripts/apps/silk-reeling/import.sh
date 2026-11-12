#!/usr/bin/env bash
# Silk Reeling's import hook: adopt its live resources into an empty Terraform
# state. Disaster recovery only: the deploy runs it (through app-hooks.sh) when
# REBUILD_STATE=true, because state normally persists in S3.
#
# Usage (from infrastructure/, with the deploy role): import.sh
# A missing resource is fine; each guard and import is handled explicitly.
set +e   # handle each guard/import explicitly; a missing resource is fine
import_silk() {
  if terraform state show "$1" >/dev/null 2>&1; then echo "in state: $1"; return; fi
  echo "importing: $1"; terraform import "$1" "$2" || echo "import skipped: $1"
}
KEY_ID=$(aws kms describe-key --key-id alias/samaydlette-com-silk-reeling --query 'KeyMetadata.KeyId' --output text 2>/dev/null || true)
if [ -n "$KEY_ID" ] && [ "$KEY_ID" != "None" ]; then
  import_silk 'aws_kms_key.silk_reeling[0]' "$KEY_ID"
  import_silk 'aws_kms_alias.silk_reeling[0]' 'alias/samaydlette-com-silk-reeling'
fi
aws iam get-role --role-name samaydlette-com-silk-reeling-role >/dev/null 2>&1 && \
  import_silk 'aws_iam_role.silk_reeling[0]' 'samaydlette-com-silk-reeling-role'
aws iam get-role-policy --role-name samaydlette-com-silk-reeling-role --policy-name samaydlette-com-silk-reeling-policy >/dev/null 2>&1 && \
  import_silk 'aws_iam_role_policy.silk_reeling[0]' 'samaydlette-com-silk-reeling-role:samaydlette-com-silk-reeling-policy'
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/samaydlette-com-silk-reeling --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q silk-reeling && \
  import_silk 'aws_cloudwatch_log_group.silk_reeling[0]' '/aws/lambda/samaydlette-com-silk-reeling'
aws logs describe-log-groups --log-group-name-prefix /aws/apigateway/samaydlette-com-silk-reeling --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q silk-reeling && \
  import_silk 'aws_cloudwatch_log_group.silk_apigw[0]' '/aws/apigateway/samaydlette-com-silk-reeling'
aws lambda get-function --function-name samaydlette-com-silk-reeling >/dev/null 2>&1 && \
  import_silk 'aws_lambda_function.silk_reeling[0]' 'samaydlette-com-silk-reeling'
# Retire any orphaned Function URL from the pre-API-Gateway deployment —
# Terraform no longer manages it (the account blocks public access anyway),
# so delete it to avoid a stray public-NONE endpoint lingering.
aws lambda get-function-url-config --function-name samaydlette-com-silk-reeling >/dev/null 2>&1 && \
  aws lambda delete-function-url-config --function-name samaydlette-com-silk-reeling 2>/dev/null && \
  echo "deleted orphaned function URL config"
# API Gateway HTTP API (replaces the Function URL).
SILK_API_ID=$(aws apigatewayv2 get-apis --query "Items[?Name=='samaydlette-com-silk-reeling'].ApiId | [0]" --output text 2>/dev/null || true)
if [ -n "$SILK_API_ID" ] && [ "$SILK_API_ID" != "None" ]; then
  import_silk 'aws_apigatewayv2_api.silk_reeling[0]' "$SILK_API_ID"
  SILK_INT_ID=$(aws apigatewayv2 get-integrations --api-id "$SILK_API_ID" --query 'Items[0].IntegrationId' --output text 2>/dev/null || true)
  [ -n "$SILK_INT_ID" ] && [ "$SILK_INT_ID" != "None" ] && \
    import_silk 'aws_apigatewayv2_integration.silk_reeling[0]' "$SILK_API_ID/$SILK_INT_ID"
  SILK_ROUTE_ID=$(aws apigatewayv2 get-routes --api-id "$SILK_API_ID" --query "Items[?RouteKey=='\$default'].RouteId | [0]" --output text 2>/dev/null || true)
  [ -n "$SILK_ROUTE_ID" ] && [ "$SILK_ROUTE_ID" != "None" ] && \
    import_silk 'aws_apigatewayv2_route.silk_reeling[0]' "$SILK_API_ID/$SILK_ROUTE_ID"
  aws apigatewayv2 get-stage --api-id "$SILK_API_ID" --stage-name '$default' >/dev/null 2>&1 && \
    import_silk 'aws_apigatewayv2_stage.silk_reeling[0]' "$SILK_API_ID/\$default"
  # Cognito JWT authorizer + the /api route (Task 3).
  SILK_AUTH_ID=$(aws apigatewayv2 get-authorizers --api-id "$SILK_API_ID" --query "Items[?Name=='samaydlette-com-silk-reeling-cognito'].AuthorizerId | [0]" --output text 2>/dev/null || true)
  [ -n "$SILK_AUTH_ID" ] && [ "$SILK_AUTH_ID" != "None" ] && \
    import_silk 'aws_apigatewayv2_authorizer.silk_reeling[0]' "$SILK_API_ID/$SILK_AUTH_ID"
  SILK_API_ROUTE_ID=$(aws apigatewayv2 get-routes --api-id "$SILK_API_ID" --query "Items[?RouteKey=='ANY /api/{proxy+}'].RouteId | [0]" --output text 2>/dev/null || true)
  [ -n "$SILK_API_ROUTE_ID" ] && [ "$SILK_API_ROUTE_ID" != "None" ] && \
    import_silk 'aws_apigatewayv2_route.silk_reeling_api[0]' "$SILK_API_ID/$SILK_API_ROUTE_ID"
fi
aws lambda get-policy --function-name samaydlette-com-silk-reeling --query 'Policy' --output text 2>/dev/null | grep -q AllowApiGatewayInvoke && \
  import_silk 'aws_lambda_permission.silk_reeling_apigw[0]' 'samaydlette-com-silk-reeling/AllowApiGatewayInvoke'
# Cognito (Task 3) — ephemeral state; adopt the pool/client/domain if present.
SILK_POOL_ID=$(aws cognito-idp list-user-pools --max-results 60 --query "UserPools[?Name=='samaydlette-com-silk-reeling-users'].Id | [0]" --output text 2>/dev/null || true)
if [ -n "$SILK_POOL_ID" ] && [ "$SILK_POOL_ID" != "None" ]; then
  import_silk 'aws_cognito_user_pool.silk_reeling[0]' "$SILK_POOL_ID"
  SILK_CLIENT_ID=$(aws cognito-idp list-user-pool-clients --user-pool-id "$SILK_POOL_ID" --query "UserPoolClients[?ClientName=='samaydlette-com-silk-reeling-spa'].ClientId | [0]" --output text 2>/dev/null || true)
  [ -n "$SILK_CLIENT_ID" ] && [ "$SILK_CLIENT_ID" != "None" ] && \
    import_silk 'aws_cognito_user_pool_client.silk_reeling[0]' "${SILK_POOL_ID}/${SILK_CLIENT_ID}"
fi
aws cognito-idp describe-user-pool-domain --domain samaydlette-com-silk-reeling --query 'DomainDescription.UserPoolId' --output text 2>/dev/null | grep -q . && \
  import_silk 'aws_cognito_user_pool_domain.silk_reeling[0]' 'samaydlette-com-silk-reeling'
echo "Silk Reeling import step complete"
