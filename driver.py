from aws_sigv4_client import AwsSigV4Client
from aws_sigv4_client import AwsServiceRequest
from aws_sigv4_client import AwsCredentials
import logging
import requests
import json
import os
import time


API_GATEWAY_BASE_PATH = ''
USERNAME=''
PASSWORD=''

def read_credentials():
    credentials = None
    if os.path.isfile('credentials.tmp.json'):
        with open("credentials.tmp.json", "r") as temp_credentials_store:
            data = temp_credentials_store.read()
        credentials = json.loads(data) if data else {}
        required_credential_keys = ('secret_key', 'session_token', 'access_key_id', 'expiration')
        if not all(k in credentials for k in required_credential_keys):
            logging.info('Missing required keys in credentials recovered from credentials.tmp.json. Found: {}'
                         .format(credentials))
            # set to None so we trigger a new login call
            credentials = None
        if credentials_expired(credentials):
            logging.info('credentials in credentials.tmp.json expired, ignoring them')
            credentials = None
    return credentials


def credentials_expired(credentials):
    expired = True
    now = int(time.time())
    credentials_expiry = int(credentials['expiration'])
    diff = credentials_expiry - now
    if diff > 0:
        logging.info("The stored credentials expire in {} seconds".format(diff))
        expired = False
    else:
        logging.info("The stored credentials expired {} seconds ago".format(abs(diff)))
    return expired


def refresh_credentials(username, password):
    payload = json.dumps({'username': username, 'password': password})
    login_response = requests.post("{}/login".format(API_GATEWAY_BASE_PATH), data=payload)
    if login_response.status_code == 200:
        response_payload = json.loads(login_response.text)['payload']
        with open("credentials.tmp.json", "w") as temp_credentials_store:
            temp_credentials_store.write(json.dumps(response_payload))
    else:
        raise Exception("Unable to retrieve login credentials, server response: {}".format(login_response.text))
    return response_payload

def main():
    logging.basicConfig(
        filename='aws-sigv4-client.log',
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(name)s %(message)s'
    )

    credentials = read_credentials()
    if not credentials:
        credentials = refresh_credentials(USERNAME, PASSWORD)

    request = AwsServiceRequest(
        verb='GET',
        service='execute-api',
        region='us-west-2',
        endpoint='{}/cafes'.format(API_GATEWAY_BASE_PATH),
        # optional API Gateway API Key: http://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-api-keys.html
        api_key=None
    )

    awsCredentials = AwsCredentials(credentials)

    client = AwsSigV4Client()
    client.make_request(request, awsCredentials)

    logging.info('Finished')


if __name__ == '__main__':
    main()
