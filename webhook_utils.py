# -*- coding: utf-8 -*-
#
# Copyright 2019 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import sys

from base64 import b64encode


def create_kms_key(client, alias, description):
    try:
        response = client.describe_key(KeyId='alias/' + alias)
        key_id = response['KeyMetadata']['KeyId']
        key_arn = response['KeyMetadata']['Arn']
    except Exception:
        response = client.create_key(
            Description=description
        )

        key_id = response['KeyMetadata']['KeyId']
        key_arn = response['KeyMetadata']['Arn']

        client.create_alias(
            AliasName='alias/' + alias,
            TargetKeyId=key_id
        )

    return key_id, key_arn


def create_role(
    client, role_name, policy_name, role_policy, assume_role_policy
):
    """Create or retrieve role and attach policy."""
    roles = [role['RoleName'] for role in client.list_roles()['Roles']]

    if role_name in roles:
        role = client.get_role(
            RoleName=role_name
        )['Role']
    else:
        role = client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy)
         )['Role']

    policies = client.list_role_policies(RoleName=role_name)['PolicyNames']

    if policy_name not in policies:
        client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(role_policy)
        )

    return role['Arn']


def get_key_policy(account_id, function_name, role):
    policy = {
      'Version': '2012-10-17',
      'Id': '{function_name}-key-policy'.format(function_name=function_name),
      'Statement': [
        {
          'Sid': 'Enable IAM User Permissions',
          'Effect': 'Allow',
          'Principal': {
            'AWS': 'arn:aws:iam::{account_id}:root'.format(
                account_id=account_id
            )
          },
          'Action': 'kms:*',
          'Resource': '*'
        },
        {
          'Sid': 'Allow use of the key',
          'Effect': 'Allow',
          'Principal': {
            'AWS': 'arn:aws:iam::{account_id}:role/{role}'.format(
                account_id=account_id,
                role=role
            )
          },
          'Action': [
            'kms:Encrypt',
            'kms:Decrypt',
            'kms:ReEncrypt*',
            'kms:GenerateDataKey*',
            'kms:DescribeKey'
          ],
          'Resource': '*'
        },
        {
          'Sid': 'Allow attachment of persistent resources',
          'Effect': 'Allow',
          'Principal': {
            'AWS': 'arn:aws:iam::{account_id}:role/{role}'.format(
                account_id=account_id,
                role=role
            )
          },
          'Action': [
            'kms:CreateGrant',
            'kms:ListGrants',
            'kms:RevokeGrant'
          ],
          'Resource': '*',
          'Condition': {
            'Bool': {
              'kms:GrantIsForAWSResource': 'true'
            }
          }
        }
      ]
    }

    return json.dumps(policy)


def get_lambda_assume_role_policy():
    policy = {
      'Version': '2012-10-17',
      'Statement': [
        {
          'Effect': 'Allow',
          'Principal': {
            'Service': 'lambda.amazonaws.com'
          },
          'Action': 'sts:AssumeRole'
        }
      ]
    }

    return policy


def get_lambda_ses_policy(account_id, function_name, region):
    ses_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': [
                    'ses:SendEmail',
                ],
                'Resource': '*'
            },
            {
                'Effect': 'Allow',
                'Action': 'logs:CreateLogGroup',
                'Resource': 'arn:aws:logs:{region}:{account_id}:*'.format(
                    region=region,
                    account_id=account_id
                )
            },
            {
                'Effect': 'Allow',
                'Action': [
                    'logs:CreateLogStream',
                    'logs:PutLogEvents'
                ],
                'Resource': [
                    'arn:aws:logs:{region}:{account_id}:'
                    'log-group:/aws/lambda/{function_name}:*'.format(
                        region=region,
                        account_id=account_id,
                        function_name=function_name
                    )
                ]
            }
        ]
    }

    return ses_policy


def kms_encrypt(client, value, key_id):
    enc_value = b64encode(
        client.encrypt(
            Plaintext=value, KeyId=key_id
        )["CiphertextBlob"]
    )

    return enc_value.decode()


def update_progress(message, progress=0, success=True):
    if progress == 100:
        end = '\n'
    else:
        end = ''

    if success:
        print('\x1b[2K\rProgress: [{0}] {1}% complete'.format(message, progress), end=end)
    else:
        print('\x1b[2K\rProgress: {0}'.format(message), end='\n')
        sys.exit(1)
