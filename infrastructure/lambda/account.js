'use strict';

// The published inventory carries ACCOUNT in place of the AWS account ID
// (scripts/_redact.py). Where this Lambda needs a callable ARN from it, it fills
// in its own account, read from the ARN it was invoked under. Nothing is filled
// from configuration, so the Lambda can only ever address resources in the
// account it runs in.
//
// Kept free of AWS-SDK imports, like canonical.js and divergence.js, so the
// tests run it under plain node.

const PLACEHOLDER = 'ACCOUNT';

function accountOf(invokedFunctionArn) {
    // arn:aws:lambda:<region>:<account>:function:<name>[:<qualifier>]
    const parts = String(invokedFunctionArn || '').split(':');
    const account = parts.length >= 7 && parts[0] === 'arn' ? parts[4] : '';
    if (!/^[0-9]{12}$/.test(account)) {
        throw new Error('cannot read the account from the invoked function ARN');
    }
    return account;
}

function withAccount(arn, account) {
    // Only the account field of an ARN is filled; a native_id that is not an ARN,
    // or already carries an account, is returned unchanged.
    const parts = String(arn || '').split(':');
    if (parts.length < 6 || parts[0] !== 'arn' || parts[4] !== PLACEHOLDER) {
        return arn;
    }
    parts[4] = account;
    return parts.join(':');
}

module.exports = { accountOf, withAccount, PLACEHOLDER };
