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

import boto3
import secrets
import time
import uuid

from utils import (
    create_kms_key,
    create_role,
    get_key_policy,
    get_lambda_assume_role_policy,
    get_lambda_ses_policy,
    kms_encrypt,
    update_progress
)
from zipfile import ZipFile

request_secret = secrets.token_hex(20)

function_name = input('Enter function name (git-email-hook): ') \
                or 'git-email-hook'

ses_region = input('Enter SES region name (us-east-1): ') or 'us-east-1'

if ses_region not in ('us-east-1', 'us-west-2', 'eu-west-1'):
    update_progress(
        'SES region must be one of: us-east-1, us-west-2 or eu-west-1.',
        success=False
    )

source_email = input('Enter source email: ')
if not source_email:
    update_progress('Source email is required.', success=False)

access_key_id = input('Enter AWS Access Key ID (blank for default): ')
secret_access_key = input('Enter AWS Secret Access Key (blank for default): ')

kwargs = {'region_name': ses_region}

if access_key_id:
    kwargs['aws_access_key_id'] = access_key_id

if secret_access_key:
    kwargs['aws_secret_access_key'] = secret_access_key

# Get session and clients
session = boto3.Session(**kwargs)
ag_client = session.client('apigateway')
lambda_client = session.client('lambda')
kms_client = session.client('kms')
iam_client = session.client('iam')
account_id = session.client('sts').get_caller_identity().get('Account')

update_progress('Acquired boto3 sessions.', progress=10)

# Create role
role_arn = create_role(
    iam_client,
    function_name,
    function_name,
    get_lambda_ses_policy(
        account_id,
        function_name,
        ses_region
    ),
    get_lambda_assume_role_policy()
)

update_progress('Created Lambda role.', progress=20)

# Create KMS key
key_id, key_arn = create_kms_key(
    kms_client,
    function_name,
    'Lambda git email hook encryption/decryption Key,'
)

# GetRole is not usable to ensure role exists (as a waiter)
# so must retry put_key_policy until success. It takes ~5 seconds
# for role to be usable.
end = time.time() + 60
while time.time() < end:
    try:
        kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=get_key_policy(
                account_id,
                function_name,
                function_name
            )
        )
    except:
        time.sleep(2)
    else:
        break
else:
    update_progress(
        'Timeout while putting key policy on KMS key.',
        success=False
    )

update_progress('Created KMS encryption key.', progress=30)

# Create Lambda
enc_secret = kms_encrypt(kms_client, request_secret, key_id)
enc_email = kms_encrypt(kms_client, source_email, key_id)

with ZipFile('webhook.zip', mode='w') as f:
    f.write('webhook.py')

with open('webhook.zip', 'rb') as f:
    code = f.read()

lambda_client.create_function(
    FunctionName=function_name,
    Runtime='python3.7',
    Role=role_arn,
    Handler='webhook.handle_request',
    Code={'ZipFile': code},
    Environment={
        'Variables': {
            'SES_REGION': ses_region,
            'REQUEST_SECRET': enc_secret,
            'SOURCE_EMAIL': enc_email
        }
    },
    Timeout=30,
    Publish=True
)

update_progress('Created Lambda function.', progress=40)

# Create REST API
api = ag_client.create_rest_api(
   name=function_name
)

parent_resource_id = ag_client.get_resources(
    restApiId=api['id']
)['items'][0]['id']

resource = ag_client.create_resource(
    restApiId=api['id'],
    parentId=parent_resource_id,
    pathPart='v1'
)

ag_client.put_method(
    restApiId=api['id'],
    resourceId=resource['id'],
    httpMethod='POST',
    authorizationType='NONE'
)

update_progress('Created REST API.', progress=50)

# Integrate function with API
uri = 'arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/' \
      'arn:aws:lambda:{region}:{account_id}:function:{function_name}/' \
      'invocations'

uri = uri.format(
    region=ses_region,
    account_id=account_id,
    function_name=function_name
)

ag_client.put_integration(
    restApiId=api['id'],
    resourceId=resource['id'],
    httpMethod='POST',
    type='AWS_PROXY',
    integrationHttpMethod='POST',
    uri=uri
)

update_progress('Function integrated with API.', progress=60)

# Put POST method response
ag_client.put_method_response(
    restApiId=api['id'],
    resourceId=resource['id'],
    httpMethod='POST',
    statusCode='200',
)

update_progress('Added POST method response.', progress=70)

# Add permissions to function
source_arn = 'arn:aws:execute-api:{region}:{account_id}:{api_id}/*/POST/v1'

source_arn = source_arn.format(
    region=ses_region,
    account_id=account_id,
    api_id=api['id']
)

lambda_client.add_permission(
    FunctionName=function_name,
    StatementId=uuid.uuid4().hex,
    Action='lambda:InvokeFunction',
    Principal='apigateway.amazonaws.com',
    SourceArn=source_arn
)

update_progress('Added API permissions to function.', progress=80)

# Create default deployment
deployment = ag_client.create_deployment(
    restApiId=api['id'],
    stageName='default'
)

update_progress('Created default API deployment.', progress=90)

# Format REST endpoint URL
endpoint = 'https://{api_id}.execute-api.{region}.amazonaws.com/' \
           '{stage}/{resource}'

endpoint = endpoint.format(
    api_id=api['id'],
    region=ses_region,
    stage='default',
    resource='v1'
)

update_progress(
    'Deployed function and REST API in {region}.'.format(region=ses_region),
    progress=100
)
print(
    'Secret key: {key}'.format(key=request_secret)
)
print(
    'REST Endpoint: {endpoint}'.format(endpoint=endpoint)
)
