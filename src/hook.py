#!/usr/bin/env python
from __future__ import print_function
import os
import sys
import hashlib
import hmac
import json
import base64
import time
import logging

import boto3

import http.server
import socketserver
import simplejson
from urllib.parse import urljoin

# Add the lib directory to the path for Lambda to load our libs
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))
from requests import Session, HTTPError  # NOQA
from requests.packages.urllib3.util.retry import Retry  # NOQA
from requests.adapters import HTTPAdapter  # NOQA

log = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

class StaticRetry(Retry):
    def sleep(self):
        time.sleep(3)


class WebhookHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(self.headers)

        # Sending an '200 OK' response
        self.send_response(200)

        return

    def do_POST(self):
        event = {}
        jenkins_url = os.getenv('JENKINS_URL')
        webhook_secret = os.getenv('WEBHOOK_SECRET')
        webhook_path = os.getenv('WEBHOOK_PATH', '')

        jenkins_url = urljoin(jenkins_url, webhook_path)

        log.info("Proxying the webhook request to the upstream url %s", jenkins_url)
        
        log.info(self.headers)

        length = int(self.headers['content-length'])
        post_body = self.rfile.read(length)
        
        event['payload'] = post_body

        event = {**self.headers, **event}
        self.relay_github(event, jenkins_url, webhook_secret)
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write("{}".encode(encoding='utf_8'))

        return

    def relay_github(self, event, jenkins_url, webhook_secret):
        verified = verify_signature(webhook_secret,
                                    event['X-Hub-Signature'],
                                    event['payload'])
        log.info('Signature verified: {}'.format(verified))

        if not verified:
            requests_session = Session()
            retries = StaticRetry(total=40)
            requests_session.mount(jenkins_url, HTTPAdapter(max_retries=retries))
            response = requests_session.post(jenkins_url,
                                            headers={
                                                'Content-Type': 'application/json',
                                                'X-GitHub-Delivery': event['X-GitHub-Delivery'],
                                                'X-GitHub-Event': event['X-GitHub-Event'],
                                                'X-Hub-Signature':  event['X-Hub-Signature']
                                            },
                                            data=event['payload'])
            log.debug(response)
            response.raise_for_status()
        else:
            log.error('Failed to verify the signature with the given secret')


def verify_signature(secret, signature, payload):
    computed_hash = hmac.new(secret.encode('ascii'), payload , hashlib.sha1)
    computed_signature = '='.join(['sha1', computed_hash.hexdigest()])
    return hmac.compare_digest(computed_signature.encode('ascii'), signature.encode('ascii'))


def relay_github(event, requests_session, jenkins_url, webhook_secret):
    verified = verify_signature(webhook_secret,
                                event['x_hub_signature'],
                                event['payload'])
    print('Signature verified: {}'.format(verified))

    if verified:
        response = requests_session.post(jenkins_url,
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

    jenkins_url = os.getenv('JENKINS_URL', event['jenkins_url'])
    webhook_secret = os.getenv('WEBHOOK_SECRET', event['secret'])

    event['payload'] = base64.b64decode(event['payload'])
    requests_session = Session()
    retries = StaticRetry(total=40)
    requests_session.mount(jenkins_url, HTTPAdapter(max_retries=retries))

    if event.get('service') == 'quay':
        relay_quay(event, requests_session)
    if event.get('service') == 'sqs':
        relay_sqs(event)
    else:
        relay_github(event, requests_session, jenkins_url, webhook_secret)
    print('Successfully relayed payload')


if __name__ == '__main__':
    service_port = os.getenv('SERVICE_PORT', 8000)

    log.info("Starting HTTP service on port %s", service_port)
    handler = WebhookHttpRequestHandler

    http_server = socketserver.TCPServer(("", service_port), handler)

    # Star the server
    http_server.serve_forever()
