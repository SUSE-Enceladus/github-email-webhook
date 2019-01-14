# GitHub Email Webhook

This package provides a Python Lambda function which handles GitHub
webhooks. It creates and sends an email to the provided mailing list/email.
The reason for the function is to replace the GitHub email service which is
now deprecated.

## Requirements

- boto3

## Install

Prior to deployment ensure that you have boto3 installed. If boto3 is
configured with a default account you will not be required to input the
access key id and secret access key during deployment. For more information
see the [boto3 docs](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#shared-credentials-file). 

To install the function and REST API call: `python deploy.py`.

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
