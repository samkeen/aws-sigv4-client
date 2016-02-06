from aws_sigv4_client import AwsSigV4Client
from aws_sigv4_client import AwsServiceRequest
from aws_sigv4_client import AwsCredentials
import logging


def main():
    logging.basicConfig(
        filename='aws-sigv4-client.log',
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(name)s %(message)s'
    )

    request = AwsServiceRequest(
        verb='GET',
        service='execute-api',
        region='us-west-2',
        endpoint='<YOUR API GATEWAY ENDPOINT>',
    )

    credentials = AwsCredentials(
        access_key_id='<YOUR TMP ACCESS KEY>',
        secret_access_key='<YOUR TMP SECRET ACCESS_KEY>',
        session_token='<YOUR SESSION TOKEN>'
    )

    client = AwsSigV4Client()
    client.make_request(request, credentials)

    logging.info('Finished')


if __name__ == '__main__':
    main()
