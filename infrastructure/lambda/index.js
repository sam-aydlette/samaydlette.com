// =============================================================================
// RUNTIME KSI SIGNAL EMITTER
// =============================================================================
// This Lambda is the "continuous" half of cATO on this site. The deploy-time
// signal at /.well-known/ksi-signal.json says what was deployed and what was
// validated *at deploy time*. This function validates that the live AWS
// configuration *still matches* that claim, and publishes a fresh runtime
// signal at /.well-known/ksi-signal-runtime.json on every invocation.
//
// Both signals conform to the same schema, so a portfolio consumer joins
// validations on component_refs without caring which emitter produced them.
//
// Policy evaluation uses the same Rego source as the deploy-time gate. The
// CI workflow compiles `infrastructure/policies.rego` to `policy.wasm` via
// `opa build -t wasm` and bundles it into this Lambda's deployment zip. At
// runtime the Lambda loads the Wasm module via @open-policy-agent/opa-wasm
// and evaluates each cloud component's live configuration against the same
// rules the deploy gate enforced. There is no JavaScript port of the rules;
// drift between deploy-time and runtime evaluation is therefore structurally
// impossible.
// =============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { loadPolicy } = require('@open-policy-agent/opa-wasm');
const {
    S3Client,
    GetBucketEncryptionCommand,
    GetBucketVersioningCommand,
    GetPublicAccessBlockCommand,
    GetBucketTaggingCommand,
    GetObjectCommand,
    PutObjectCommand,
} = require('@aws-sdk/client-s3');
const {
    CloudFrontClient,
    GetDistributionConfigCommand,
} = require('@aws-sdk/client-cloudfront');
const {
    KMSClient,
    SignCommand,
    GetPublicKeyCommand,
} = require('@aws-sdk/client-kms');
const { canonicalize } = require('./canonical');

const SIGNAL_VERSION = '1.0.0';
const SCHEMA_URL = 'https://samaydlette.com/.well-known/ksi-signal.schema.json';

// Lazy-loaded policy. Loaded once per Lambda container, reused across
// invocations within the container's lifetime.
let cachedPolicy = null;
let cachedPolicyVersion = null;

async function getPolicy() {
    if (cachedPolicy) return { policy: cachedPolicy, version: cachedPolicyVersion };
    const wasmPath = path.join(__dirname, 'policy.wasm');
    const wasmBytes = fs.readFileSync(wasmPath);
    cachedPolicy = await loadPolicy(wasmBytes);
    // Use a stable hash of the wasm bytes as the policy version. Two Lambda
    // containers running the same wasm produce the same version.
    cachedPolicyVersion = crypto.createHash('sha256').update(wasmBytes).digest('hex').slice(0, 12);
    return { policy: cachedPolicy, version: cachedPolicyVersion };
}

// =============================================================================
// LIVE-CONFIG → REGO INPUT TRANSFORMERS
// =============================================================================
// Each transformer queries the AWS API for one cloud component and produces
// the {resource: {...}} shape `policies.rego` expects. The Rego rules are
// identical to the ones the deploy-time gate evaluates, so the transformer's
// only job is to make live config look like a Terraform plan resource.
// =============================================================================

const REQUIRED_TAGS = ['Environment', 'CostCenter', 'DataClassification', 'Owner'];

async function buildS3ResourceInput(s3, bucketName, tfName) {
    let encryptionEnabled = false;
    try {
        const enc = await s3.send(new GetBucketEncryptionCommand({ Bucket: bucketName }));
        const algorithm = enc?.ServerSideEncryptionConfiguration?.Rules?.[0]
            ?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm;
        encryptionEnabled = algorithm === 'AES256' || algorithm === 'aws:kms';
    } catch (err) {
        console.warn(`GetBucketEncryption failed for ${bucketName}: ${err.name}`);
    }

    let versioningEnabled = false;
    try {
        const ver = await s3.send(new GetBucketVersioningCommand({ Bucket: bucketName }));
        versioningEnabled = ver?.Status === 'Enabled';
    } catch (err) {
        console.warn(`GetBucketVersioning failed for ${bucketName}: ${err.name}`);
    }

    let publicAccessBlocked = false;
    try {
        const pab = await s3.send(new GetPublicAccessBlockCommand({ Bucket: bucketName }));
        const cfg = pab?.PublicAccessBlockConfiguration ?? {};
        publicAccessBlocked = Boolean(
            cfg.BlockPublicAcls && cfg.BlockPublicPolicy &&
            cfg.IgnorePublicAcls && cfg.RestrictPublicBuckets
        );
    } catch (err) {
        console.warn(`GetPublicAccessBlock failed for ${bucketName}: ${err.name}`);
    }

    const tags = {};
    try {
        const tagging = await s3.send(new GetBucketTaggingCommand({ Bucket: bucketName }));
        for (const t of tagging?.TagSet ?? []) tags[t.Key] = t.Value;
    } catch (err) {
        // NoSuchTagSet is a normal AWS response when no tags are set; treat
        // as empty tag map. Rego will flag missing required tags.
        if (err.name !== 'NoSuchTagSet') {
            console.warn(`GetBucketTagging failed for ${bucketName}: ${err.name}`);
        }
    }

    return {
        type: 'aws_s3_bucket',
        name: tfName || bucketName,
        tags,
        encryption_enabled: encryptionEnabled,
        versioning_enabled: versioningEnabled,
        public_access_blocked: publicAccessBlocked,
    };
}

async function buildCloudFrontResourceInput(cf, distributionId, tfName) {
    let viewerProtocolPolicy = '';
    let minimumProtocolVersion = '';
    const tags = {};

    try {
        const out = await cf.send(new GetDistributionConfigCommand({ Id: distributionId }));
        const cfg = out?.DistributionConfig ?? {};
        viewerProtocolPolicy = cfg?.DefaultCacheBehavior?.ViewerProtocolPolicy ?? '';
        minimumProtocolVersion = cfg?.ViewerCertificate?.MinimumProtocolVersion ?? '';
    } catch (err) {
        console.warn(`GetDistributionConfig failed for ${distributionId}: ${err.name}`);
    }

    // CloudFront tags require a separate API call (cloudfront:ListTagsForResource).
    // The Lambda role does not currently grant that action; the Rego rule for
    // missing tags only applies to S3 buckets in the current policy, so this
    // is acceptable. If the policy expands to require CloudFront tags, the
    // role and this transformer both need to grow.

    return {
        type: 'aws_cloudfront_distribution',
        name: tfName || distributionId,
        tags,
        viewer_protocol_policy: viewerProtocolPolicy,
        minimum_protocol_version: minimumProtocolVersion,
    };
}

// =============================================================================
// POLICY EVALUATION
// =============================================================================
// One Rego evaluation per cloud component. The `compliance_report` rule in
// policies.rego returns a single object with `compliant`, `total_violations`,
// `violations[]`, and a few summary fields. We extract `compliant` and
// `violations[]` for the KSI signal's validation entry.
// =============================================================================

async function evaluateResource(policy, resourceInput) {
    const result = policy.evaluate({ resource: resourceInput });
    const report = result?.[0]?.result ?? {};
    return {
        compliant: report.compliant !== false,
        violations: Array.isArray(report.violations) ? report.violations : [],
    };
}

// =============================================================================
// SIGNAL CONSTRUCTION
// =============================================================================

function findComponent(components, type, predicate) {
    return components.find((c) => c.type === type && predicate(c));
}

async function streamToString(stream) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf-8');
}

async function readDeploySignal(s3, bucketName) {
    const out = await s3.send(new GetObjectCommand({
        Bucket: bucketName,
        Key: '.well-known/ksi-signal.json',
    }));
    const body = await streamToString(out.Body);
    return JSON.parse(body);
}

async function buildRuntimeSignal(deploySignal, s3, cf, policy, policyVersion) {
    const components = deploySignal.components ?? [];
    const validations = [];
    let validationIdx = 0;

    // S3 bucket: there is one in this system.
    const bucket = findComponent(components, 'object_store', () => true);
    if (bucket) {
        const bucketName =
            bucket.attributes?.id ||
            (bucket.native_id?.split(':::').pop()) ||
            process.env.S3_BUCKET;
        const tfName = bucket.attributes?.tf_name;
        const input = await buildS3ResourceInput(s3, bucketName, tfName);
        const result = await evaluateResource(policy, input);
        validations.push({
            validation_id: `r-${String(validationIdx++).padStart(4, '0')}`,
            policy: { id: 'terraform.compliance', version: `wasm-${policyVersion}` },
            result: result.compliant ? 'pass' : 'fail',
            component_refs: [bucket.component_id],
            violations: result.violations,
        });
    }

    // CloudFront distribution: same pattern.
    const dist = findComponent(components, 'cdn_distribution', () => true);
    if (dist) {
        const distributionId = dist.attributes?.id;
        if (distributionId) {
            const tfName = dist.attributes?.tf_name;
            const input = await buildCloudFrontResourceInput(cf, distributionId, tfName);
            const result = await evaluateResource(policy, input);
            validations.push({
                validation_id: `r-${String(validationIdx++).padStart(4, '0')}`,
                policy: { id: 'terraform.compliance', version: `wasm-${policyVersion}` },
                result: result.compliant ? 'pass' : 'fail',
                component_refs: [dist.component_id],
                violations: result.violations,
            });
        }
    }

    const provenance = {
        builder: {
            id: 'aws-lambda://runtime-ksi-emitter',
            run_id: process.env.AWS_LAMBDA_LOG_STREAM_NAME || 'unknown',
            version: process.env.AWS_LAMBDA_FUNCTION_VERSION || 'unknown',
        },
        source: {
            repository: deploySignal.provenance?.source?.repository || 'unknown',
            commit: deploySignal.provenance?.source?.commit || '0000000',
            ref: 'runtime',
        },
    };

    return {
        $schema: SCHEMA_URL,
        signal_version: SIGNAL_VERSION,
        signal_id: crypto.randomUUID(),
        emitted_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        emitter: 'runtime',
        csp: deploySignal.csp || 'aws',
        system_id: deploySignal.system_id,
        provenance,
        components,
        validations,
    };
}

// =============================================================================
// SIGNING (POAM-002)
// =============================================================================
// The runtime signal is signed with an AWS KMS asymmetric key (ECC NIST P-256,
// SIGN_VERIFY) so a consumer can verify it cryptographically rather than trust
// the well-known URL implicitly. The signature covers the canonical form of the
// signal with `provenance.attestation` absent; the signature object is then
// placed in `provenance.attestation`. A verifier reproduces the canonical bytes
// by deleting `provenance.attestation`, canonicalizing, and checking the
// signature against the published public key. The canonicalization recipe lives
// in ./canonical.js so verifiers and tests can reuse it without the AWS SDK.

// Wrap SPKI DER public-key bytes as PEM.
function derToPem(der) {
    const b64 = Buffer.from(der).toString('base64');
    const lines = b64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----\n`;
}

// Sign the signal in place: returns a copy with provenance.attestation set.
async function signSignal(signal, kms, keyArn) {
    const canonical = Buffer.from(canonicalize(signal), 'utf8');
    const digest = crypto.createHash('sha256').update(canonical).digest();
    const { Signature } = await kms.send(new SignCommand({
        KeyId: keyArn,
        Message: digest,
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ECDSA_SHA_256',
    }));
    return {
        ...signal,
        provenance: {
            ...signal.provenance,
            attestation: {
                type: 'kms-ecdsa-p256',
                algorithm: 'ECDSA_SHA_256',
                key_id: keyArn,
                canonicalization: 'sorted-keys JSON, no whitespace; provenance.attestation omitted before signing',
                signature: Buffer.from(Signature).toString('base64'),
                public_key_url: 'https://samaydlette.com/.well-known/runtime-signing-pubkey.pem',
                signed_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
            },
        },
    };
}

// Publish the signing public key so consumers can verify without trusting us.
async function publishPublicKey(kms, s3, bucketName, keyArn) {
    const { PublicKey } = await kms.send(new GetPublicKeyCommand({ KeyId: keyArn }));
    await s3.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: '.well-known/runtime-signing-pubkey.pem',
        Body: derToPem(PublicKey),
        ContentType: 'application/x-pem-file',
        CacheControl: 'public, max-age=300',
    }));
}

// =============================================================================
// HANDLER
// =============================================================================

exports.handler = async (event, context) => {
    console.log('Runtime KSI emitter started');

    const bucketName = process.env.S3_BUCKET;
    if (!bucketName) {
        throw new Error('S3_BUCKET env var is required');
    }

    const region = process.env.AWS_REGION || 'us-east-2';
    const s3 = new S3Client({ region });
    // CloudFront API is global, billed in us-east-1.
    const cf = new CloudFrontClient({ region: 'us-east-1' });

    const { policy, version: policyVersion } = await getPolicy();
    console.log(`Loaded compiled Rego policy (sha256:${policyVersion}...)`);

    let deploySignal;
    try {
        deploySignal = await readDeploySignal(s3, bucketName);
    } catch (err) {
        console.error('Could not read deploy-time signal', err);
        return {
            statusCode: 503,
            body: JSON.stringify({
                message: 'No deploy-time signal to validate against',
                compliant: false,
                error: err.message,
            }),
        };
    }

    let runtimeSignal = await buildRuntimeSignal(deploySignal, s3, cf, policy, policyVersion);

    // Sign the signal (POAM-002) and publish the verifying public key. The signing
    // key is resolved by its stable alias, derived from the bucket/domain
    // (alias/<domain-with-dashes>-runtime-signing). Deriving it from S3_BUCKET
    // avoids depending on a separately-injected env var; kms:Sign is authorized
    // against the underlying key ARN regardless of resolving via the alias. If
    // signing fails (e.g. the key is unavailable), the signal is published
    // unsigned rather than failing the compliance-monitor run.
    // Publish the public key BEFORE signing, so a signed signal is never
    // published without the key needed to verify it: if either step fails, the
    // signal stays unsigned (the catch leaves runtimeSignal unmodified).
    const signingKeyAlias = 'alias/' + bucketName.replace(/\./g, '-') + '-runtime-signing';
    try {
        const kms = new KMSClient({ region });
        await publishPublicKey(kms, s3, bucketName, signingKeyAlias);
        runtimeSignal = await signSignal(runtimeSignal, kms, signingKeyAlias);
        console.log(`Public key published; runtime signal signed with ${signingKeyAlias}`);
    } catch (err) {
        console.error(`Signing failed (${signingKeyAlias}); publishing unsigned`, err);
    }

    await s3.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: '.well-known/ksi-signal-runtime.json',
        Body: JSON.stringify(runtimeSignal, null, 2) + '\n',
        ContentType: 'application/json',
        CacheControl: 'public, max-age=300',
    }));

    const passes = runtimeSignal.validations.filter((v) => v.result === 'pass').length;
    const fails = runtimeSignal.validations.filter((v) => v.result === 'fail').length;
    const compliant = fails === 0;

    console.log(`Runtime signal published: ${passes} pass, ${fails} fail`);

    return {
        statusCode: 200,
        body: JSON.stringify({
            message: 'Runtime KSI signal published',
            compliant,
            signal_id: runtimeSignal.signal_id,
            policy_version: policyVersion,
            validation_summary: { pass: passes, fail: fails },
        }),
    };
};
