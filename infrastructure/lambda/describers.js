'use strict';

// =============================================================================
// LIVE-CONFIG READERS FOR EVERY MACHINE COMPONENT TYPE
// =============================================================================
// One reader per inventory component type. Each reads the live configuration
// through `ctx.aws` (an adapter of plain async functions; index.js builds it
// from the AWS SDK, the tests from fixtures) and returns the policy inputs to
// evaluate, in the shape the Rego gate reads: a Terraform resource type and
// the live facts under the same Terraform attribute names (`values`), plus
// tags. The same compiled policy then judges the live account exactly as the
// deploy gate judged the plan.
//
// A failed read is never evidence that a setting is off. Every attribute that
// could not be read is listed in `read_errors`; the gate reports it as
// resource_read_error (category input), which the divergence block counts as
// unassessed and reconciliation invariant (n) refuses to count as validated.
//
// Only SDK error NAMES are kept (never messages), because the signal is public.
//
// Kept free of AWS-SDK imports, like canonical.js and divergence.js, so the
// tests run it under plain node.
// =============================================================================

const { withAccount } = require('./account');

// Terraform types the tagging rules require tags on (policy config
// taggable_types). A reader for one of these must supply tags or declare them
// unread; tags come from one Resource Groups Tagging API sweep (ctx.tags) or,
// for IAM roles, from GetRole.
function needsTags(ctx, tfType) {
    return (ctx.taggableTypes || []).includes(tfType);
}

function errName(err) {
    return (err && err.name) || 'UnknownError';
}

// Resolve a published, account-redacted ARN to a callable one.
function arnOf(ctx, component) {
    return withAccount(component.native_id || '', ctx.account);
}

function regionOf(ctx, component) {
    const parts = String(component.native_id || '').split(':');
    return (parts[0] === 'arn' && parts[3]) || component.attributes?.region || ctx.region;
}

function attrId(component) {
    return component.attributes?.id;
}

function attachTags(ctx, resource, arn, tags) {
    if (!needsTags(ctx, resource.type)) return resource;
    const found = tags || (ctx.tags && ctx.tags.get(arn));
    if (found) {
        resource.tags = found;
        resource.tags_all = found;
    } else {
        resource.read_errors = [...(resource.read_errors || []), 'tags'];
    }
    return resource;
}

function resource(type, component, values, readErrors) {
    const r = {
        type,
        name: component.attributes?.tf_name || component.component_id,
        values,
    };
    if (readErrors.length > 0) r.read_errors = readErrors;
    return r;
}

async function read(errors, attr, fn) {
    try {
        return await fn();
    } catch (err) {
        errors.push(attr);
        return undefined;
    }
}

function decodeDocument(doc) {
    // IAM returns policy documents URL-encoded.
    if (typeof doc !== 'string') return doc;
    try {
        return decodeURIComponent(doc);
    } catch (err) {
        return doc;
    }
}

// --- IAM --------------------------------------------------------------------

async function iamRole(ctx, c) {
    const errors = [];
    const name = attrId(c);
    const role = await read(errors, 'assume_role_policy', () => ctx.aws.iam.getRole(name));
    const attached = await read(errors, 'attached_policy_arns', () => ctx.aws.iam.listAttachedRolePolicies(name));
    const values = { name };
    if (role) values.assume_role_policy = decodeDocument(role.AssumeRolePolicyDocument);
    if (attached) values.attached_policy_arns = attached;
    const r = resource('aws_iam_role', c, values, errors);
    if (!role) {
        // Tags come from the same GetRole call; nothing to attach.
        r.read_errors = [...(r.read_errors || []), 'tags'];
        return [r];
    }
    const tags = {};
    for (const t of role.Tags || []) tags[t.Key] = t.Value;
    return [attachTags(ctx, r, null, tags)];
}

// The name an attached policy's ARN ends in (arn:...:policy[/path]/<name>).
function policyName(arn) {
    return String(arn || '').split('/').pop();
}

// Managed-policy attachments: the inventory records each attachment's policies
// by name only (their ARNs carry the account ID). The holder's live attached
// policies are listed and compared by name; every recorded policy must still
// be attached, or the attachment is reported unread (it cannot be validated),
// never passed. The live ARNs of the recorded policies are the input, under
// the same runtime attribute the role and group readers use.
async function iamAttachment(ctx, c, tfType) {
    const errors = [];
    const attrs = c.attributes || {};
    const group = tfType === 'aws_iam_group_policy_attachment';
    const holder = group ? attrs.attached_to_group : attrs.attached_to_role;
    const expected = (attrs.attached_policies || []).map((p) => p.policy_name).filter(Boolean);
    const values = {};
    if (!holder || expected.length === 0) {
        errors.push('attached_policies');
        return [resource(tfType, c, values, errors)];
    }
    const live = await read(errors, 'attached_policies', () => (group
        ? ctx.aws.iam.listAttachedGroupPolicies(holder)
        : ctx.aws.iam.listAttachedRolePolicies(holder)));
    if (live) {
        const byName = new Map(live.map((arn) => [policyName(arn), arn]));
        if (expected.every((n) => byName.has(n))) {
            values.attached_policy_arns = expected.map((n) => byName.get(n));
        } else {
            errors.push('attached_policies');
        }
    }
    return [resource(tfType, c, values, errors)];
}

async function iamPolicy(ctx, c) {
    const errors = [];
    const tfType = c.attributes?.tf_type || 'aws_iam_role_policy';
    if (tfType === 'aws_iam_role_policy_attachment' || tfType === 'aws_iam_group_policy_attachment') {
        return iamAttachment(ctx, c, tfType);
    }
    let doc;
    if (tfType === 'aws_iam_policy') {
        // No managed-policy component is inventoried today, so the role holds
        // no iam:GetPolicyVersion grant; one that appears is reported unread
        // (and fails invariant n) until the grant and a reader are added.
        errors.push('policy');
    } else {
        // Inline policies: the Terraform id is "<role or group>:<policy name>".
        const id = String(attrId(c) || '');
        const at = id.indexOf(':');
        const [holder, policyName_] = at < 0 ? [id, ''] : [id.slice(0, at), id.slice(at + 1)];
        const get = tfType === 'aws_iam_group_policy'
            ? () => ctx.aws.iam.getGroupPolicy(holder, policyName_)
            : () => ctx.aws.iam.getRolePolicy(holder, policyName_);
        doc = await read(errors, 'policy', get);
    }
    const values = {};
    if (doc !== undefined) values.policy = decodeDocument(doc);
    // The holder, under its Terraform attribute name, from the same inventory id
    // the read used (no further call): the log-access rule keys its allowlist on it.
    if (tfType === 'aws_iam_role_policy' || tfType === 'aws_iam_group_policy') {
        const id = String(attrId(c) || '');
        const at = id.indexOf(':');
        if (at > 0) values[tfType === 'aws_iam_group_policy' ? 'group' : 'role'] = id.slice(0, at);
    }
    return [resource(tfType, c, values, errors)];
}

async function iamGroup(ctx, c) {
    const errors = [];
    const name = attrId(c);
    const attached = await read(errors, 'attached_policy_arns', () => ctx.aws.iam.listAttachedGroupPolicies(name));
    const inline = await read(errors, 'inline_policies', async () => {
        const names = await ctx.aws.iam.listGroupPolicies(name);
        const docs = [];
        for (const n of names) docs.push(decodeDocument(await ctx.aws.iam.getGroupPolicy(name, n)));
        return docs;
    });
    const values = { name };
    if (attached) values.attached_policy_arns = attached;
    if (inline) values.inline_policies = inline;
    return [resource('aws_iam_group', c, values, errors)];
}

async function oidcProvider(ctx, c) {
    const errors = [];
    const p = await read(errors, 'client_id_list', () => ctx.aws.iam.getOpenIDConnectProvider(arnOf(ctx, c)));
    const values = {};
    if (p) {
        values.client_id_list = p.ClientIDList || [];
        values.url = p.Url;
    }
    return [resource('aws_iam_openid_connect_provider', c, values, errors)];
}

// --- compute ------------------------------------------------------------------

// The function's own configuration, plus a second unit for its deployed code
// package: live CodeSha256 against the hash the deploy inventoried. That unit
// names the packages the deployment package holds (attributes.deployed_in), so
// the integrity check is evidence about them too.
async function lambdaFunction(ctx, c) {
    const errors = [];
    const name = c.attributes?.function_name || attrId(c);
    const cfg = await read(errors, 'kms_key_arn', () => ctx.aws.lambda.getFunctionConfiguration(name));
    const values = { function_name: name };
    if (cfg) {
        values.kms_key_arn = cfg.KMSKeyArn || '';
        values.runtime = cfg.Runtime;
    }
    try {
        const url = await ctx.aws.lambda.getFunctionUrlConfig(name);
        if (url) values.function_url_auth_type = url.AuthType;
    } catch (err) {
        // No URL configured is the expected answer; anything else is unread.
        if (errName(err) !== 'ResourceNotFoundException') errors.push('function_url');
    }
    const fn = attachTags(ctx, resource('aws_lambda_function', c, values, errors), arnOf(ctx, c));

    const pkgErrors = cfg ? [] : ['code_sha256'];
    const pkgValues = {};
    if (cfg) pkgValues.code_sha256 = cfg.CodeSha256 || '';
    if (c.attributes?.code_sha256) pkgValues.expected_code_sha256 = c.attributes.code_sha256;
    const pkg = resource('lambda_deployment_package', c, pkgValues, pkgErrors);
    const packageRefs = (ctx.components || [])
        .filter((p) => p.attributes?.deployed_in === c.component_id)
        .map((p) => p.component_id)
        .sort();
    return [
        { inputs: [fn], refs: [c.component_id] },
        { inputs: [pkg], refs: [c.component_id, ...packageRefs], policy: 'package-integrity' },
    ];
}

// --- logging, monitoring, scheduling ------------------------------------------

async function logGroup(ctx, c) {
    const errors = [];
    const name = attrId(c);
    const lg = await read(errors, 'kms_key_id', () => ctx.aws.logs.describeLogGroup(name, regionOf(ctx, c)));
    const values = { name };
    if (lg) {
        values.retention_in_days = lg.retentionInDays || 0;
        values.kms_key_id = lg.kmsKeyId || '';
    } else if (!errors.includes('kms_key_id')) {
        errors.push('kms_key_id');
    }
    return [attachTags(ctx, resource('aws_cloudwatch_log_group', c, values, errors), arnOf(ctx, c).replace(/:\*$/, ''))];
}

async function auditTrail(ctx, c) {
    const errors = [];
    const arn = arnOf(ctx, c);
    const trail = await read(errors, 'trail', () => ctx.aws.cloudtrail.getTrail(arn, regionOf(ctx, c)));
    const status = trail ? await read(errors, 'trail', () => ctx.aws.cloudtrail.getTrailStatus(arn, regionOf(ctx, c))) : undefined;
    const values = {};
    if (trail && status) {
        values.enable_logging = status.IsLogging === true;
        values.is_multi_region_trail = trail.IsMultiRegionTrail === true;
        values.enable_log_file_validation = trail.LogFileValidationEnabled === true;
    }
    return [resource('aws_cloudtrail', c, values, [...new Set(errors)])];
}

async function metricAlarm(ctx, c) {
    const errors = [];
    const a = await read(errors, 'alarm_actions', () => ctx.aws.cloudwatch.describeAlarm(attrId(c), regionOf(ctx, c)));
    const values = {};
    if (a) {
        values.actions_enabled = a.ActionsEnabled === true;
        values.alarm_actions = a.AlarmActions || [];
    } else if (!errors.length) {
        errors.push('alarm_actions');
    }
    return [attachTags(ctx, resource('aws_cloudwatch_metric_alarm', c, values, errors), arnOf(ctx, c))];
}

async function eventSchedule(ctx, c) {
    const errors = [];
    const rule = await read(errors, 'state', () => ctx.aws.events.describeRule(attrId(c), regionOf(ctx, c)));
    const values = {};
    if (rule) values.state = rule.State;
    return [attachTags(ctx, resource('aws_cloudwatch_event_rule', c, values, errors), arnOf(ctx, c))];
}

async function notificationTopic(ctx, c) {
    const errors = [];
    const arn = arnOf(ctx, c);
    const attrs = await read(errors, 'kms_master_key_id', () => ctx.aws.sns.getTopicAttributes(arn, regionOf(ctx, c)));
    const values = {};
    if (attrs) values.kms_master_key_id = attrs.KmsMasterKeyId || '';
    return [attachTags(ctx, resource('aws_sns_topic', c, values, errors), arn)];
}

async function messageQueue(ctx, c) {
    const errors = [];
    // The inventory's queue URL carries ACCOUNT in place of the account ID.
    const url = String(attrId(c) || '').replace('/ACCOUNT/', `/${ctx.account}/`);
    const attrs = await read(errors, 'encryption', () => ctx.aws.sqs.getQueueAttributes(url, regionOf(ctx, c)));
    const values = {};
    if (attrs) {
        values.sqs_managed_sse_enabled = attrs.SqsManagedSseEnabled === 'true';
        values.kms_master_key_id = attrs.KmsMasterKeyId || '';
    }
    return [attachTags(ctx, resource('aws_sqs_queue', c, values, errors), arnOf(ctx, c))];
}

async function kvTable(ctx, c) {
    const errors = [];
    const pitr = await read(errors, 'point_in_time_recovery', () => ctx.aws.dynamodb.describeContinuousBackups(attrId(c), regionOf(ctx, c)));
    const values = {};
    if (pitr !== undefined) values.point_in_time_recovery = [{ enabled: pitr === 'ENABLED' }];
    return [resource('aws_dynamodb_table', c, values, errors)];
}

// --- identity, keys, edge -------------------------------------------------------

async function identityProvider(ctx, c) {
    const errors = [];
    const pool = await read(errors, 'mfa_configuration', () => ctx.aws.cognito.describeUserPool(attrId(c), regionOf(ctx, c)));
    const values = {};
    if (pool) {
        values.mfa_configuration = pool.MfaConfiguration;
        values.password_policy = [{ minimum_length: pool.Policies?.PasswordPolicy?.MinimumLength ?? 0 }];
        values.admin_create_user_config = [{
            allow_admin_create_user_only: pool.AdminCreateUserConfig?.AllowAdminCreateUserOnly === true,
        }];
    } else {
        errors.push('password_policy', 'admin_create_user_config');
    }
    return [attachTags(ctx, resource('aws_cognito_user_pool', c, values, errors), arnOf(ctx, c))];
}

async function kmsKey(ctx, c) {
    const errors = [];
    const arn = arnOf(ctx, c);
    const region = regionOf(ctx, c);
    const meta = await read(errors, 'enable_key_rotation', () => ctx.aws.kms.describeKey(arn, region));
    const values = {};
    if (meta) {
        values.customer_master_key_spec = meta.KeySpec || meta.CustomerMasterKeySpec;
        values.is_enabled = meta.KeyState === 'Enabled';
        if (values.customer_master_key_spec === 'SYMMETRIC_DEFAULT') {
            const rotating = await read(errors, 'enable_key_rotation', () => ctx.aws.kms.getKeyRotationStatus(arn, region));
            if (rotating !== undefined) values.enable_key_rotation = rotating === true;
        }
    }
    return [attachTags(ctx, resource('aws_kms_key', c, values, [...new Set(errors)]), arn)];
}

async function apiGateway(ctx, c) {
    const apiId = attrId(c);
    const region = regionOf(ctx, c);
    const arn = arnOf(ctx, c);
    const inputs = [attachTags(ctx, resource('aws_apigatewayv2_api', c, { id: apiId }, []), arn)];
    const errors = [];
    const stages = await read(errors, 'stages', () => ctx.aws.apigw.getStages(apiId, region));
    const routes = await read(errors, 'routes', () => ctx.aws.apigw.getRoutes(apiId, region));
    if (errors.length) {
        // Reported as unread on the API itself, so no stage or route rule
        // judges configuration that was never observed.
        const unread = resource('aws_apigatewayv2_api', c, { id: apiId }, errors);
        unread.name = `${unread.name}/config`;
        inputs.push(attachTags(ctx, unread, arn));
    }
    for (const s of stages || []) {
        const values = {
            name: s.StageName,
            access_log_settings: s.AccessLogSettings?.DestinationArn
                ? [{ destination_arn: s.AccessLogSettings.DestinationArn }] : [],
            default_route_settings: [{
                throttling_rate_limit: s.DefaultRouteSettings?.ThrottlingRateLimit ?? 0,
                throttling_burst_limit: s.DefaultRouteSettings?.ThrottlingBurstLimit ?? 0,
            }],
        };
        const stage = resource('aws_apigatewayv2_stage', c, values, []);
        stage.name = `${stage.name}/${s.StageName}`;
        inputs.push(attachTags(ctx, stage, `${arn}/stages/${s.StageName}`));
    }
    for (const rt of routes || []) {
        const route = resource('aws_apigatewayv2_route', c, {
            route_key: rt.RouteKey,
            authorization_type: rt.AuthorizationType || 'NONE',
        }, []);
        route.name = `${route.name}/${rt.RouteKey}`;
        inputs.push(route);
    }
    return [{ inputs, refs: [c.component_id] }];
}

async function dnsZone(ctx, c) {
    const errors = [];
    const status = await read(errors, 'dnssec_status', () => ctx.aws.route53.getDnssecStatus(attrId(c)));
    const values = {};
    if (status !== undefined) values.dnssec_status = status;
    return [resource('aws_route53_zone', c, values, errors)];
}

async function tlsCertificate(ctx, c) {
    const errors = [];
    const cert = await read(errors, 'status', () => ctx.aws.acm.describeCertificate(arnOf(ctx, c), regionOf(ctx, c)));
    const values = {};
    if (cert) {
        values.status = cert.Status;
        // Whole days of validity left. Derived here, not in Rego: the Wasm
        // host implements no time builtins (time.parse_rfc3339_ns throws).
        const notAfter = cert.NotAfter ? new Date(cert.NotAfter).getTime() : NaN;
        if (!Number.isNaN(notAfter)) values.days_to_expiry = Math.floor((notAfter - (ctx.now ? ctx.now() : Date.now())) / 86400000);
        else errors.push('days_to_expiry');
    }
    return [resource('aws_acm_certificate', c, values, errors)];
}

// Component type -> reader. object_store, cdn_distribution and secrets_manager
// keep their original readers in index.js.
const READERS = {
    iam_role: iamRole,
    iam_policy: iamPolicy,
    iam_group: iamGroup,
    oidc_provider: oidcProvider,
    function: lambdaFunction,
    log_group: logGroup,
    audit_log_trail: auditTrail,
    metric_alarm: metricAlarm,
    event_schedule: eventSchedule,
    notification_topic: notificationTopic,
    message_queue: messageQueue,
    kv_table: kvTable,
    identity_provider: identityProvider,
    kms_key: kmsKey,
    api_gateway: apiGateway,
    dns_zone: dnsZone,
    tls_certificate: tlsCertificate,
};

// A reader returns either policy inputs (one validation for the component) or
// units ({inputs, refs, policy?}). Normalize to units.
async function describe(ctx, component) {
    const reader = READERS[component.type];
    if (!reader) return null;
    const out = await reader(ctx, component);
    if (out.length > 0 && out[0].inputs) return out;
    return [{ inputs: out, refs: [component.component_id] }];
}

// Evaluate every unit and fold each into one validation: fail when any of its
// inputs is non-compliant, carrying every violation. `evaluate` is the
// compiled policy (index.js) or a stub (tests).
async function validateComponents(ctx, components, evaluate, policyId, policyVersion, nextId) {
    const validations = [];
    for (const component of components) {
        const units = await describe(ctx, component);
        if (!units) continue;
        for (const unit of units) {
            let compliant = true;
            const violations = [];
            const applies = new Set();
            for (const input of unit.inputs) {
                const result = await evaluate(input);
                if (!result.compliant) compliant = false;
                violations.push(...result.violations);
                for (const a of result.applies || []) applies.add(a);
            }
            const validation = {
                validation_id: nextId(),
                policy: { id: policyId, version: policyVersion },
                result: compliant && violations.length === 0 ? 'pass' : 'fail',
                component_refs: unit.refs,
                violations,
            };
            // The rules whose condition applied (custom.credit: applies_to): the
            // SDR credits such a rule's runtime method only where it applied.
            if (applies.size > 0) validation.applies = [...applies].sort();
            validations.push(validation);
        }
    }
    return validations;
}

module.exports = { READERS, describe, validateComponents, decodeDocument };
