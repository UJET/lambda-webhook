import argparse
import json
import sys
import threading
import time

import boto3
import requests
from requests.exceptions import ConnectionError


class SqsReceiver(object):
    def __init__(self, options):
        self.options = options
        self.debug = options.debug

    def deliver_message(self, message):
        body = json.loads(message['Body'])
        url = self.options.webhook_url or body.get('jenkins_url')
        if self.debug:
            print("Posting message to webhook.")
        for t in [0, 1, 2, 4, 8, 16]:
            time.sleep(t)
            try:
                response = requests.post(url, headers=body.get('headers'), data=body.get('data'))
                if self.debug:
                    print("Post result: {}".format(repr(response)))
                break
            except ConnectionError as e:
                print("ConnectionError: {}".format(e))

    def run(self):
        sqs = boto3.client('sqs', self.options.region)
        queue_url = sqs.get_queue_url(QueueName=self.options.queue).get('QueueUrl')
        if self.debug:
            print("Using queue URL: {}".format(queue_url))
        while True:
            receive = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                VisibilityTimeout=300,
                WaitTimeSeconds=self.options.wait_time_seconds,
            )
            message_list = receive.get('Messages', [])
            if message_list:
                deliver_message_threads = list()
                receipt_handles = list()
                for message in message_list:
                    t = threading.Thread(target=self.deliver_message, args=[message])
                    deliver_message_threads.append(t)
                    t.start()
                    receipt_handles.append(
                        {'Id': message['MessageId'], 'ReceiptHandle': message['ReceiptHandle']}
                    )

                for t in deliver_message_threads:
                    t.join(timeout=120)

                result = sqs.delete_message_batch(QueueUrl=queue_url, Entries=receipt_handles)
                if self.debug:
                    print("delete_message_batch() -> {}".format(repr(result)))

                if self.debug:
                    print("Webhooks found on previous attempt. Checking for more.")

            elif self.options.run_forever:
                time.sleep(30)
            else:
                if self.debug:
                    print("No messages received. Exiting.")
                break


def cmd():
    parser = argparse.ArgumentParser(
        description="Lambda webhook SQS relay. Receives and delivers webhooks placed in SQS by lambda-webhook.")

    parser.add_argument('queue', type=str, help='SQS Queue name')
    parser.add_argument('--region', type=str, default='us-west-2', help='SQS Queue region')
    parser.add_argument(
        '--webhook-url', type=str,
        help='Override webhook receiver URL. URL may be provided in queue message.'
    )
    parser.add_argument('--wait-time-seconds', type=int, default=15,
                        help='SQS receive_message WaitTimeSeconds')
    parser.add_argument('--run-forever', action='store_true', default=False,
                        help="Run until process is interrupted. ")
    parser.add_argument('-d', dest='debug', action='store_true', default=False, help='Debug')

    options = parser.parse_args(sys.argv[1:])
    if options.debug:
        print("Argparse options: {}".format(repr(options)))

    receiver = SqsReceiver(options)
    receiver.run()


if __name__ == '__main__':
    cmd()
