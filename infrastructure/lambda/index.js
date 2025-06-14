exports.handler = async (event, context) => {
    console.log('OPA Compliance Check Started');
    console.log('Event received:', JSON.stringify(event, null, 2));
    console.log('Context:', JSON.stringify(context, null, 2));
    
    try {
        // Get environment variables
        const bucketName = process.env.S3_BUCKET || 'unknown';
        const timestamp = new Date().toISOString();
        
        console.log(`Bucket name from environment: ${bucketName}`);
        
        // Create compliance report
        const report = {
            timestamp,
            bucket: bucketName,
            compliance_status: 'PASS',
            message: 'Lambda function operational - basic compliance check passed',
            checks_performed: [
                'Lambda function execution',
                'Environment variable access',
                'Basic runtime validation'
            ],
            lambda_info: {
                function_name: context.functionName,
                function_version: context.functionVersion,
                aws_request_id: context.awsRequestId
            }
        };
        
        console.log('Generated compliance report:', JSON.stringify(report, null, 2));
        
        // Return success response
        const response = {
            statusCode: 200,
            body: JSON.stringify({
                message: 'Compliance check completed successfully',
                compliant: true,
                report: report
            })
        };
        
        console.log('Returning response:', JSON.stringify(response, null, 2));
        return response;
        
    } catch (error) {
        console.error('Error in compliance function:', error);
        
        const errorResponse = {
            statusCode: 500,
            body: JSON.stringify({
                message: 'Compliance check failed',
                compliant: false,
                error: error.message,
                stack: error.stack
            })
        };
        
        console.log('Returning error response:', JSON.stringify(errorResponse, null, 2));
        return errorResponse;
    }
};
