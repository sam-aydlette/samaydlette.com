// lambda/index.js - OPA Compliance Lambda Function

const AWS = require('aws-sdk');
const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const s3 = new AWS.S3();

// OPA binary should be included in Lambda layer or deployment package
const OPA_BINARY = '/opt/opa'; // Assuming OPA is in a Lambda layer

exports.handler = async (event, context) => {
    console.log('Starting OPA compliance check...');
    console.log('Event:', JSON.stringify(event, null, 2));
    
    try {
        const bucketName = process.env.S3_BUCKET;
        if (!bucketName) {
            throw new Error('S3_BUCKET environment variable not set');
        }
        
        // Step 1: Validate infrastructure compliance
        const infrastructureCompliance = await checkInfrastructureCompliance(bucketName);
        
        // Step 2: Check Section 508 compliance by scanning HTML files
        const section508Compliance = await checkSection508Compliance(bucketName);
        
        // Step 3: Generate comprehensive report
        const report = {
            timestamp: new Date().toISOString(),
            bucket: bucketName,
            infrastructure: infrastructureCompliance,
            section508: section508Compliance,
            overall_compliant: infrastructureCompliance.compliant && section508Compliance.compliant
        };
        
        console.log('Compliance Report:', JSON.stringify(report, null, 2));
        
        // Step 4: Store report in S3
        await storeComplianceReport(bucketName, report);
        
        // Step 5: Send notifications if violations found
        if (!report.overall_compliant) {
            await sendComplianceAlert(report);
        }
        
        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'Compliance check completed',
                compliant: report.overall_compliant,
                violations: (infrastructureCompliance.violations || []).concat(section508Compliance.violations || [])
            })
        };
        
    } catch (error) {
        console.error('Error in compliance check:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({
                message: 'Compliance check failed',
                error: error.message
            })
        };
    }
};

async function checkInfrastructureCompliance(bucketName) {
    console.log('Checking infrastructure compliance...');
    
    try {
        // Get bucket configuration
        const bucketDetails = await getBucketConfiguration(bucketName);
        
        // Prepare input for OPA
        const opaInput = {
            resource: bucketDetails
        };
        
        // Evaluate with OPA
        const opaResult = await evaluateWithOPA(opaInput, 'infrastructure');
        
        return opaResult;
        
    } catch (error) {
        console.error('Infrastructure compliance check failed:', error);
        return {
            compliant: false,
            violations: [{
                type: 'infrastructure_check_failed',
                message: `Infrastructure compliance check failed: ${error.message}`,
                severity: 'HIGH'
            }]
        };
    }
}

async function checkSection508Compliance(bucketName) {
    console.log('Checking Section 508 compliance...');
    
    try {
        // Get list of HTML files from S3
        const htmlFiles = await getHtmlFiles(bucketName);
        
        let allViolations = [];
        let compliant = true;
        
        // Check each HTML file
        for (const file of htmlFiles) {
            console.log(`Checking ${file}...`);
            
            const htmlContent = await getS3Object(bucketName, file);
            
            const opaInput = {
                html_content: htmlContent,
                file_name: file
            };
            
            const result = await evaluateWithOPA(opaInput, 'section508');
            
            if (!result.compliant) {
                compliant = false;
                allViolations = allViolations.concat(result.violations.map(v => ({
                    ...v,
                    file: file
                })));
            }
        }
        
        return {
            compliant: compliant,
            violations: allViolations,
            files_checked: htmlFiles.length
        };
        
    } catch (error) {
        console.error('Section 508 compliance check failed:', error);
        return {
            compliant: false,
            violations: [{
                type: 'section508_check_failed',
                message: `Section 508 compliance check failed: ${error.message}`,
                severity: 'HIGH'
            }]
        };
    }
}

async function getBucketConfiguration(bucketName) {
    console.log(`Getting configuration for bucket: ${bucketName}`);
    
    const config = {
        type: 'aws_s3_bucket',
        name: bucketName,
        tags: {},
        versioning_enabled: false,
        encryption_enabled: false
    };
    
    try {
        // Get bucket tagging
        const tagging = await s3.getBucketTagging({ Bucket: bucketName }).promise();
        config.tags = tagging.TagSet.reduce((acc, tag) => {
            acc[tag.Key] = tag.Value;
            return acc;
        }, {});
    } catch (error) {
        console.log('No tags found or error getting tags:', error.message);
    }
    
    try {
        // Get bucket versioning
        const versioning = await s3.getBucketVersioning({ Bucket: bucketName }).promise();
        config.versioning_enabled = versioning.Status === 'Enabled';
    } catch (error) {
        console.log('Error getting versioning:', error.message);
    }
    
    try {
        // Get bucket encryption
        const encryption = await s3.getBucketEncryption({ Bucket: bucketName }).promise();
        config.encryption_enabled = encryption.ServerSideEncryptionConfiguration.Rules.length > 0;
    } catch (error) {
        console.log('Error getting encryption:', error.message);
    }
    
    return config;
}

async function getHtmlFiles(bucketName) {
    const params = {
        Bucket: bucketName
    };
    
    const objects = await s3.listObjectsV2(params).promise();
    
    return objects.Contents
        .filter(obj => obj.Key.endsWith('.html'))
        .map(obj => obj.Key)
        .slice(0, 10); // Limit to first 10 files to avoid timeout
}

async function getS3Object(bucketName, key) {
    const params = {
        Bucket: bucketName,
        Key: key
    };
    
    const result = await s3.getObject(params).promise();
    return result.Body.toString();
}

async function evaluateWithOPA(input, policyType) {
    return new Promise((resolve, reject) => {
        // Write input to temporary file
        const inputFile = `/tmp/input-${Date.now()}.json`;
        fs.writeFileSync(inputFile, JSON.stringify(input));
        
        // Policy file should be included in deployment package
        const policyFile = path.join(__dirname, 'policies.rego');
        
        const opaCommand = `${OPA_BINARY} eval -d ${policyFile} -i ${inputFile} "data.terraform.compliance.compliance_report"`;
        
        exec(opaCommand, (error, stdout, stderr) => {
            // Clean up temp file
            try {
                fs.unlinkSync(inputFile);
            } catch (cleanupError) {
                console.warn('Failed to cleanup temp file:', cleanupError.message);
            }
            
            if (error) {
                console.error('OPA execution error:', error);
                console.error('OPA stderr:', stderr);
                reject(new Error(`OPA evaluation failed: ${error.message}`));
                return;
            }
            
            try {
                const result = JSON.parse(stdout);
                console.log('OPA Result:', JSON.stringify(result, null, 2));
                
                // Extract the compliance report from OPA result
                if (result.result && result.result.length > 0) {
                    resolve(result.result[0]);
                } else {
                    // Fallback for simpler evaluation
                    resolve({
                        compliant: true,
                        violations: [],
                        message: 'No violations found'
                    });
                }
            } catch (parseError) {
                console.error('Failed to parse OPA output:', parseError);
                console.error('OPA stdout:', stdout);
                reject(new Error(`Failed to parse OPA output: ${parseError.message}`));
            }
        });
    });
}

async function storeComplianceReport(bucketName, report) {
    const reportKey = `compliance-reports/${new Date().toISOString().split('T')[0]}/report-${Date.now()}.json`;
    
    const params = {
        Bucket: bucketName,
        Key: reportKey,
        Body: JSON.stringify(report, null, 2),
        ContentType: 'application/json',
        ServerSideEncryption: 'AES256'
    };
    
    try {
        await s3.putObject(params).promise();
        console.log(`Compliance report stored at: s3://${bucketName}/${reportKey}`);
    } catch (error) {
        console.error('Failed to store compliance report:', error);
        // Don't throw - this shouldn't fail the whole check
    }
}

async function sendComplianceAlert(report) {
    console.log('Sending compliance alert...');
    
    // In a real implementation, you might send to SNS, Slack, etc.
    // For now, just log the alert
    const violationCount = (report.infrastructure.violations || []).length + 
                          (report.section508.violations || []).length;
    
    const alertMessage = {
        type: 'COMPLIANCE_VIOLATION',
        timestamp: report.timestamp,
        bucket: report.bucket,
        violation_count: violationCount,
        high_severity_count: violationCount, // Simplified
        message: `Compliance violations detected in ${report.bucket}. ${violationCount} issues found.`,
        report_summary: {
            infrastructure_compliant: report.infrastructure.compliant,
            section508_compliant: report.section508.compliant,
            overall_compliant: report.overall_compliant
        }
    };
    
    console.log('COMPLIANCE ALERT:', JSON.stringify(alertMessage, null, 2));
    
    // TODO: Implement actual alerting mechanism
    // Examples:
    // - Send to SNS topic
    // - Post to Slack webhook
    // - Create JIRA ticket
    // - Send email via SES
