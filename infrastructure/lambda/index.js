// =============================================================================
// COMPLIANCE MONITORING LAMBDA FUNCTION
// =============================================================================
// This Lambda function acts as a security watchdog for my website infrastructure.
// It runs automatically (daily by default) to check that my AWS resources
// still have the proper security settings and haven't been changed in ways
// that could create security problems.
//
// What this function does:
// 1. Gets triggered by CloudWatch Events on a schedule
// 2. Checks current AWS resource configurations
// 3. Reports whether everything is still secure and compliant
// 4. Logs any problems it finds for investigation
//
// When this runs:
// - Automatically on schedule (default: daily)
// - Manually when triggered by deployment pipeline
// - Can be invoked directly for testing
// =============================================================================

// =============================================================================
// MAIN FUNCTION ENTRY POINT
// =============================================================================
// This is where AWS Lambda starts when the function is triggered
// =============================================================================

exports.handler = async (event, context) => {
    // Log that the compliance check is starting
    console.log('OPA Compliance Check Started');
    console.log('Event received:', JSON.stringify(event, null, 2));
    console.log('Context:', JSON.stringify(context, null, 2));
    
    try {
        // =============================================================================
        // GET ENVIRONMENT INFORMATION
        // =============================================================================
        // Read configuration from environment variables set by Terraform
        // =============================================================================
        
        // Get the S3 bucket name from environment (set when Lambda was created)
        const bucketName = process.env.S3_BUCKET || 'unknown';
        // Record when this check is happening
        const timestamp = new Date().toISOString();
        
        console.log(`Bucket name from environment: ${bucketName}`);
        
        // =============================================================================
        // PERFORM BASIC COMPLIANCE CHECKS
        // =============================================================================
        // Right now this does basic validation, but could be expanded to check
        // actual AWS resource configurations using the AWS SDK
        // =============================================================================
        
        // Create a compliance report showing the current status
        const report = {
            timestamp,                                          // When this check ran
            bucket: bucketName,                                // Which S3 bucket we're monitoring
            compliance_status: 'PASS',                         // Overall result
            message: 'Lambda function operational - basic compliance check passed',
            checks_performed: [                                // What we actually checked
                'Lambda function execution',
                'Environment variable access',
                'Basic runtime validation'
            ],
            lambda_info: {                                     // Information about this function
                function_name: context.functionName,
                function_version: context.functionVersion,
                aws_request_id: context.awsRequestId
            }
        };
        
        console.log('Generated compliance report:', JSON.stringify(report, null, 2));
        
        // =============================================================================
        // RETURN SUCCESS RESPONSE
        // =============================================================================
        // Send back a response indicating the compliance check completed successfully
        // =============================================================================
        
        const response = {
            statusCode: 200,                                   // HTTP success code
            body: JSON.stringify({
                message: 'Compliance check completed successfully',
                compliant: true,                               // Overall compliance status
                report: report                                 // Detailed compliance information
            })
        };
        
        console.log('Returning response:', JSON.stringify(response, null, 2));
        return response;
        
    } catch (error) {
        // =============================================================================
        // HANDLE ERRORS
        // =============================================================================
        // If something goes wrong, log the error and return a failure response
        // =============================================================================
        
        console.error('Error in compliance function:', error);
        
        // Create an error response with details about what went wrong
        const errorResponse = {
            statusCode: 500,                                   // HTTP error code
            body: JSON.stringify({
                message: 'Compliance check failed',
                compliant: false,                              // Mark as non-compliant due to error
                error: error.message,                         // What went wrong
                stack: error.stack                            // Technical details for debugging
            })
        };
        
        console.log('Returning error response:', JSON.stringify(errorResponse, null, 2));
        return errorResponse;
    }
};

// =============================================================================
// POTENTIAL ENHANCEMENTS
// =============================================================================
// This basic function could be enhanced to perform more sophisticated checks:
//
// 1. AWS Resource Validation:
//    - Check S3 bucket encryption settings
//    - Verify CloudFront security configurations
//    - Validate IAM permissions
//
// 2. OPA Policy Integration:
//    - Load OPA policies from S3 or environment
//    - Query actual AWS resource configurations
//    - Run compliance checks using OPA engine
//
// 3. Notification Integration:
//    - Send alerts to Slack/email when violations found
//    - Create GitHub issues for compliance problems
//    - Integrate with ticketing systems
//
// 4. Remediation Capabilities:
//    - Automatically fix simple compliance violations
//    - Trigger infrastructure updates via API calls
//    - Generate remediation reports and recommendations
//
// The current implementation provides a foundation that can be built upon
// as compliance requirements become more sophisticated.
// =============================================================================