#!/usr/bin/env python
from __future__ import print_function
import os
import sys
import hashlib
import hmac
import json
import base64
import time

import boto3

# Add the lib directory to the path for Lambda to load our libs
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))
from requests import Session, HTTPError  # NOQA
from requests.packages.urllib3.util.retry import Retry  # NOQA
from requests.adapters import HTTPAdapter  # NOQA


class StaticRetry(Retry):
    def sleep(self):
        time.sleep(3)


def verify_signature(secret, signature, payload):
    computed_hash = hmac.new(secret.encode('ascii'), payload, hashlib.sha1)
    computed_signature = '='.join(['sha1', computed_hash.hexdigest()])
    return hmac.compare_digest(computed_signature.encode('ascii'), signature.encode('ascii'))


def relay_github(event, requests_session):
    verified = verify_signature(event['secret'],
                                event['x_hub_signature'],
                                event['payload'])
    print('Signature verified: {}'.format(verified))

    if verified:
        response = requests_session.post(event['jenkins_url'],
                                         headers={
                                            'Content-Type': 'application/json',
                                            'X-GitHub-Delivery': event['x_github_delivery'],
                                            'X-GitHub-Event': event['x_github_event'],
                                            'X-Hub-Signature':  event['x_hub_signature']
                                         },
                                         data=event['payload'])
        response.raise_for_status()
    else:
        raise HTTPError('400 Client Error: Bad Request')


def relay_quay(event, requests_session):
    response = requests_session.post(event['jenkins_url'],
                                     headers={
                                         'Content-Type': 'application/json'
                                     },
                                     data=event['payload'])
    response.raise_for_status()


def relay_sqs(event):
    sqs_queue = event.get('sqs_queue')
    sqs_region = event.get('sqs_region', 'us-west-2')
    assert sqs_queue

    sqs_obj = dict(
        timestamp=int(time.time()),
        jenkins_url=event.get('jenkins_url'),
        headers={
            'Content-Type': 'application/json',
            'X-GitHub-Delivery': event['x_github_delivery'],
            'X-GitHub-Event': event['x_github_event'],
            'X-Hub-Signature': event['x_hub_signature']
        },
        data=event['payload'],
    )

    sqs = boto3.client('sqs', sqs_region)
    queue_url = sqs.get_queue_url(QueueName=sqs_queue)['QueueUrl']
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(sqs_obj).decode(),
    )


def lambda_handler(event, context):
    print('Webhook received')
    event['payload'] = base64.b64decode(event['payload'])
    requests_session = Session()
    retries = StaticRetry(total=40)
    requests_session.mount(event['jenkins_url'], HTTPAdapter(max_retries=retries))

    if event.get('service') == 'quay':
        relay_quay(event, requests_session)
    if event.get('service') == 'sqs':
        relay_sqs(event)
    else:
        relay_github(event, requests_session)
    print('Successfully relayed payload')


if __name__ == '__main__':
    pass
