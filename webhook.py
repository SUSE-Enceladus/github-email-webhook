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
import hashlib
import hmac
import json
import os

from base64 import b64decode


def kms_decrypt(client, enc_value):
    value = client.decrypt(
        CiphertextBlob=b64decode(enc_value)
    )['Plaintext']

    return value


kms_client = boto3.client('kms')

EVENT_TYPES = ('ping', 'push',)
SES_REGION = os.environ['SES_REGION']

enc_secret = os.environ['REQUEST_SECRET']
SECRET = kms_decrypt(kms_client, enc_secret)

enc_email = os.environ['SOURCE_EMAIL']
SOURCE_EMAIL = kms_decrypt(kms_client, enc_email).decode()


def send_email(data):
    repo = data['repository']
    pusher = data['pusher']

    empty_commit = '0000000000000000000000000000000000000000'
    if data['before'] == empty_commit:
        event = 'pushed a new branch'
    elif data['after'] == empty_commit:
        event = 'deleted a branch'
    else:
        event = 'pushed new commits'

    subject = f'[{repo["full_name"]}] {data["ref"]}'
    message = f'{pusher["name"]} {event} in {repo["full_name"]}\n\n' \
              f'Branch: {data["ref"]}\n' \
              f'Home:   {repo["html_url"]}\n' \
              f'Pusher: {pusher["name"]} <{pusher["email"]}>\n' \
              f'Diff:   {data["compare"]}\n\n'

    for commit in data['commits']:
        author = commit['author']
        message += f'Commit: {commit["id"]}\n' \
                   f'Message: {commit["message"]}\n' \
                   f'URL: {commit["url"]}\n' \
                   f'Author: {author["name"]} <{author["email"]}>\n' \
                   f'Date: {commit["timestamp"]}\n\n'

    try:
        client = boto3.client(
            'ses',
            region_name=SES_REGION
        )
        client.send_email(
            Source=SOURCE_EMAIL,
            ReplyToAddresses=[SOURCE_EMAIL],
            Destination={
                'ToAddresses': [SOURCE_EMAIL]
            },
            Message={
                'Subject': {
                    'Data': subject,
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {
                        'Data': message,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
    except Exception as e:
        print(e)
        return False
    else:
        return True


def validate_signature(signature, body):
    try:
        expected_sig = 'sha1=' + hmac.new(
            SECRET, msg=body.encode(), digestmod=hashlib.sha1
        ).hexdigest()

        if hmac.compare_digest(expected_sig, signature):
            return True
    except Exception as e:
        print(e)
        return False

    return False


def handle_request(event, context):
    try:
        signature = event['headers']['X-Hub-Signature']
    except KeyError:
        return {
            'statusCode': 400,
            'body': 'Missing header X-Hub-Signature.'
        }

    if not validate_signature(signature, event['body']):
        return {
            'statusCode': 403,
            'body': 'Invalid signature.'
        }

    try:
        data = json.loads(event['body'])
    except Exception:
        return {
            'statusCode': 418,
            'body': 'Data is not json.'
        }

    try:
        event_type = event['headers']['X-GitHub-Event']
    except KeyError:
        return {
            'statusCode': 400,
            'body': 'Missing header X-GitHub-Event.'
        }

    if event_type not in EVENT_TYPES:
        return {
            'statusCode': 400,
            'body': f'Event type {event_type} not supported.'
        }

    if event_type == 'ping':
        return {
            'statusCode': 200,
            'body': 'success!'
        }

    if send_email(data):
        return {
            'statusCode': 200,
            'body': 'success!'
        }
    else:
        return {
            'statusCode': 400,
            'body': 'Failed to send email.'
        }
