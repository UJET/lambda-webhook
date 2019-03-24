import unittest
import lambdawebhook.hook
import os
import json
import httpretty
import base64
from requests import HTTPError


def load_test_event():
    mypath = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(mypath, 'data/testevent.json'), 'r') as eventfile:
        githubevent = json.load(eventfile)
        githubevent['payload'] = base64.b64encode(json.dumps(githubevent['payload'], sort_keys=True).encode('ascii'))
    return githubevent


class VerifySignatureTestCase(unittest.TestCase):
    def runTest(self):
        githubevent = load_test_event()

        # Match the conversion that happens in the beginning of lambda_handler()
        githubevent['payload'] = base64.b64decode(githubevent['payload'])

        # This signature is missing the 'sha1=' prefix and will fail validation
        self.assertFalse(lambdawebhook.hook.verify_signature(githubevent['secret'],
                                                             '952548c8f23303f4925411b09b0c5d0c13d0cfb5',
                                                             githubevent['payload']))

        # This signature should validate the payload
        self.assertTrue(lambdawebhook.hook.verify_signature(githubevent['secret'],
                                                            githubevent['x_hub_signature'],
                                                            githubevent['payload']))


class LambdaHandlerTestCase(unittest.TestCase):
    @httpretty.activate
    def runTest(self):
        invalidevent = load_test_event()
        invalidevent['secret'] = 'invalidsecret'
        self.assertRaises(HTTPError, lambdawebhook.hook.lambda_handler, invalidevent, {})

        # Check return codes
        httpretty.register_uri(httpretty.POST, 'https://localhost/github-webhook/',
                               status=200)
        githubevent = load_test_event()
        self.assertIsNone(lambdawebhook.hook.lambda_handler(githubevent, {}))
