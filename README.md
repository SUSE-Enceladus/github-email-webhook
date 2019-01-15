# GitHub Email Webhook

This package provides a Python Lambda function which handles GitHub
webhooks. It creates and sends an email to the provided source email address.
The reason for the function is to replace the GitHub email service which is
now deprecated.

## Requirements

- boto3

## Setup

Prior to deployment ensure that you have boto3 installed. If boto3 is
configured with a default account you will not be required to input the
access key id and secret access key during deployment. For more information
see the [boto3 docs](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#shared-credentials-file).

The AWS account must have access to the following AWS services:

- API Gateway
- Lambda
- KMS
- IAM

## Install

To install the function and REST API call: `python deploy.py`.

During deployment the following values are used:

- **Function name** (default: git-email-hook): This is used for naming any
created resources. Name should not contain any spaces.
- **Deployment region** (default: us-east-1): This region is used to place
all resources. It must be one of: us-east-1, us-west-2 or eu-west-1. These
are the only regions where AWS SES (Simple Email Service) exists.
- **Source email** (required): The email address that will be mailed the
notification emails. This will also be the source and reply-to address. The
email must be one that you own and can verify. See
[AWS SES docs](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-email-addresses.html)
for more information on email verification.
- **Access Key ID** (optional): The AWS access key ID for the account being
used. If not supplied the script will use the default account credentials.
- **Secret Access Key** (optional): The AWS secret access key for the account
being used. If not supplied the script will use the default account
credentials.

Once the function is installed a secret key and REST API endpoint will
be provided. Use these two values to configure your GitHub repo's webhook.

For more information see the
[GitHub docs](https://developer.github.com/webhooks/creating/).

## Status

Currently the function handles the following webhook event types:

- ping
- push

## Issues/Enhancements

Please submit issues and requests to
[Github](https://github.com/SUSE-Enceladus/github-email-webhook/issues).

## License

Copyright (c) 2019 SUSE LLC.

Distributed under the terms of Apache 2.0 license, see
[LICENSE](https://github.com/SUSE-Enceladus/github-email-webhook/blob/master/LICENSE)
for details.
