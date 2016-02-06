import sys, os, base64, datetime, hashlib, hmac
import requests  # pip install requests
from urlparse import urlsplit
from urllib import urlencode
import pprint
import logging
from collections import namedtuple

logger = logging.getLogger(__name__)


# heavily inspired by: http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html #

# ************* EXAMPLE EC2 request *************
# method = 'GET'
# service = 'ec2'
# host = 'ec2.amazonaws.com'
# region = 'us-east-1'
# endpoint = 'https://ec2.amazonaws.com'
# request_parameters = 'Action=DescribeRegions&Version=2013-10-15'

class AwsServiceRequest():
    def __init__(self, **kwargs):
        self.verb = kwargs.get('verb').upper()
        self.service = kwargs.get('service')
        self.region = kwargs.get('region')
        self.endpoint = kwargs.get('endpoint')
        self.body = kwargs.get('body') or ''
        url_parts = self.parse_url(kwargs.get('endpoint'))
        self.host = url_parts['host']
        self.path = url_parts['path'] or '/'
        self.url_query_string = url_parts['query'] or ''

    def parse_url(self, url):
        url_split = urlsplit(url)
        logger.info("endpoint URL split: {}".format(url_split))
        return {
            'host': url_split.netloc,
            'path': url_split.path,
            'query': url_split.query
        }


class AwsCredentials():
    def __init__(self, **kwargs):
        self.access_key_id = kwargs.get('access_key_id')
        self.secret_access_key = kwargs.get('secret_access_key')
        self.session_token = kwargs.get('session_token')


class AwsSigV4Client():
    def __init__(self):
        self.signed_headers_list = 'host;x-amz-date'

    def make_request(self, request, credentials):
        """

        :param credentials: AwsCredentials
        :param request:Request
        :return:
        """

        # Create a date for headers and the credential string
        now_utc = datetime.datetime.utcnow()
        amzdate = now_utc.strftime('%Y%m%dT%H%M%SZ')
        datestamp = now_utc.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_request = self.generate_canonical_request(request, amzdate)
        logger.debug("canonical_request: \n{}".format(canonical_request))

        # ************* TASK 2: CREATE THE STRING TO SIGN*************
        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = '/'.join([
            datestamp,
            request.region,
            request.service,
            'aws4_request'
        ])
        string_to_sign = '\n'.join([
            algorithm,
            amzdate,
            credential_scope,
            hashlib.sha256(canonical_request).hexdigest()
        ])
        logger.debug("string_to_sign: \n{}".format(string_to_sign))
        # ************* TASK 3: CALCULATE THE SIGNATURE *************
        # Create the signing key using the function defined above.
        signing_key = self.getSignatureKey(credentials.secret_access_key, datestamp, request.region, request.service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

        # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        # The signing information can be either in a query string value or in
        # a header named Authorization. This code shows how to use a header.
        # Create authorization header and add to request headers
        authorization_header = '{} Credential={}/{}, SignedHeaders={}, Signature={}'.format(
            algorithm,
            credentials.access_key_id,
            credential_scope,
            self.signed_headers_list,
            signature
        )

        # The request can include any headers, but MUST include "host", "x-amz-date",
        # and (for this scenario) "Authorization". "host" and "x-amz-date" must
        # be included in the canonical_headers and signed_headers, as noted
        # earlier. Order here is not significant.
        # Python note: The 'host' header is added automatically by the Python 'requests' library.
        headers = {
            'x-amz-date': amzdate,
            'Authorization': authorization_header,
            'x-amz-security-token': credentials.session_token
        }

        # ************* SEND THE REQUEST *************
        request_url = '{}?{}'.format(request.endpoint, request.url_query_string)

        logger.debug('Headers: {}'.format(headers))
        logger.debug('request_url: {}'.format(request_url))
        r = requests.get(request_url, headers=headers)
        logger.debug('response status code: {}'.format(r.status_code))
        logger.debug(r.text)

    def sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def getSignatureKey(self, key, dateStamp, regionName, serviceName):
        kDate = self.sign(('AWS4' + key).encode('utf-8'), dateStamp)
        kRegion = self.sign(kDate, regionName)
        kService = self.sign(kRegion, serviceName)
        kSigning = self.sign(kService, 'aws4_request')
        return kSigning

    def generate_canonical_request(self, request, amzdate):
        """
        http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        :param request:Request
        :param amzdate:str
        :return: str
        """
        # Step 2: Create canonical URI--the part of the URI from domain to query
        # string (use '/' if no path)
        canonical_uri = request.path

        # Step 3: Create the canonical query string. In this example (a GET request),
        # request parameters are in the query string. Query string values must
        # be URL-encoded (space=%20). The parameters must be sorted by name.
        # For this example, the query string is pre-formatted in the request_parameters variable.
        canonical_querystring = request.url_query_string

        # Step 4: Create the canonical headers and signed headers. Header names
        # and value must be trimmed and lowercase, and sorted in ASCII order.
        # Note that there is a trailing \n.
        canonical_headers = 'host:{}\nx-amz-date:{}\n'.format(request.host, amzdate)

        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        # Step 6: Create payload hash (hash of the request body content)
        payload_hash = hashlib.sha256(request.body).hexdigest()
        # Step 7: Combine elements to create create canonical request
        return '\n'.join([
            request.verb,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            self.signed_headers_list,
            payload_hash
        ])
