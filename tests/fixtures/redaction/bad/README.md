Known-bad input for the publication redaction gate
(scripts/check-published-redaction.py): an inventory that still carries an AWS
account ID, in an ARN and bare. The number is the AWS documentation example
account, not a real one. The gate must exit 1 on this directory.
