#!/usr/bin/env python3
import subprocess
import urllib.request
import urllib.parse
import json
import unittest
import logging
import sys
import os
import time
import re
from getpass import getpass

username = os.getenv('CFUSER')
password = os.getenv('CFPASSWORD')

if (username is None):
    username = input("Username: ")
if (password is None):
    password = getpass()

logging.basicConfig(level=logging.INFO)


class TestTokenClient(unittest.TestCase):
    def setUp(self):
        self.app = CFApp(name='java-tokenclient-usage',
                         xsuaa_service_name='xsuaa-token-client')
        self.sampleTestHelper = SampleTestHelper(self.app)
        self.sampleTestHelper.setUp()

    def tearDown(self):
        self.sampleTestHelper.tearDown()

    def test_hello_token_client(self):
        response = self.sampleTestHelper.perform_get_request_with_token(
            'hello-token-client')
        body = response.body

        self.assertIsNotNone(body)
        self.assertRegex(body, "Access-Token: ")
        self.assertRegex(body, "Access-Token-Payload: ")
        self.assertRegex(body, "Expired-At: ")


class TestJavaSecurity(unittest.TestCase):
    def setUp(self):
        self.app = CFApp(name='java-security-usage',
                         xsuaa_service_name='xsuaa-java-security')
        self.sampleTestHelper = SampleTestHelper(self.app)
        self.sampleTestHelper.setUp()

    def tearDown(self):
        self.sampleTestHelper.tearDown()

    def test_hello_java_security(self):
        resp = self.sampleTestHelper.perform_get_request_with_token(
            'hello-java-security')
        self.assertEqual(resp.status, 403)

        self.sampleTestHelper.add_user_to_role('JAVA_SECURITY_SAMPLE_Viewer')
        resp = self.sampleTestHelper.perform_get_request_with_token(
            'hello-java-security')

        expected_response = "You ('{}') can access the application with the following scopes: '[openid, java-security-usage!t1785.Read]'.".format(
            username)
        self.assertIsNotNone(resp.body)
        self.assertEqual(resp.body, expected_response)

class TestSpringSecurity(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        app = CFApp(name='spring-security-xsuaa-usage', xsuaa_service_name='xsuaa-authentication',
            app_router_name='approuter-spring-security-xsuaa-usage')

        cls.sampleTestHelper = SampleTestHelper(app)
        cls.sampleTestHelper.setUp()

    @classmethod
    def tearDownClass(cls):
        cls.sampleTestHelper.tearDown()

    def setUp(self):
        self.sampleTestHelper = TestSpringSecurity.sampleTestHelper
    
    def test_sayHello(self):
        resp = self.sampleTestHelper.perform_get_request_with_token(
            'v1/sayHello')
        self.assertEqual(resp.status, 403)
        self.sampleTestHelper.add_user_to_role('Viewer')
        resp = self.sampleTestHelper.perform_get_request_with_token(
            'v1/sayHello')
        self.assertEqual(resp.status, 200)

class TestJavaBuildpackApiUsage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app = CFApp(name='sap-java-buildpack-api-usage', xsuaa_service_name='xsuaa-buildpack', app_router_name='approuter-sap-java-buildpack-api-usage')
        cls.sampleTestHelper = SampleTestHelper(app)
        cls.sampleTestHelper.setUp()

    @classmethod
    def tearDownClass(cls):
        cls.sampleTestHelper.tearDown()


    def test_hello_token_servlet(self):
        self.sampleTestHelper = TestJavaBuildpackApiUsage.sampleTestHelper
        resp = self.sampleTestHelper.perform_get_request_with_token('hello-token')
        self.assertEqual(resp.status, 403)
        self.sampleTestHelper.add_user_to_role('Buildpack_API_Viewer')
        resp = self.sampleTestHelper.perform_get_request_with_token('hello-token')
        self.assertEqual(resp.status, 200)
        self.assertRegex(resp.body, username)

class SampleTestHelper:

    def __init__(self, app_to_test):
        self.app_to_test = app_to_test
        vars_file = open('./vars.yml')
        self.vars_parser = VarsParser(vars_file.read())
        vars_file.close()
        self.cf_apps = CFApps()
        self.__deployed_app = None
        self.__api_access = None

    def setUp(self):
        self.app_to_test.deploy()
        time.sleep(2)  # waiting for deployed apps to be available

    def tearDown(self):
        self.app_to_test.delete()
        if self.__api_access is not None:
            self.__api_access.delete()

    def add_user_to_role(self, role):
        self.get_api_access().add_user_to_group(self.user_guid, role)

    def get_user_access_token(self):
        deployed_app = self.get_deployed_app()
        return HttpUtil().get_access_token(
            xsuaa_service_url=deployed_app.xsuaa_service_url,
            clientid=deployed_app.clientid,
            clientsecret=deployed_app.clientsecret,
            grant_type='password',
            username=username,
            password=password)

    def perform_get_request_with_token(self, path):
        url = 'https://{}-{}.{}/{}'.format(
            self.app_to_test.name,
            self.vars_parser.user_id,
            self.vars_parser.landscape_apps_domain,
            path)
        resp = HttpUtil().get_request(
            url, access_token=self.get_user_access_token())
        return resp

    def get_api_access(self):
        if (self.__api_access is None):
            deployed_app = self.get_deployed_app()
            self.__api_access = ApiAccessService(
                xsuaa_service_url=deployed_app.xsuaa_service_url, xsuaa_api_url=deployed_app.xsuaa_api_url)
            self.user_guid = self.__api_access.get_user_by_username(
                username).get('id')
        return self.__api_access

    def get_deployed_app(self):
        if (self.__deployed_app is None):
            deployed_app = self.cf_apps.app_by_name(self.app_to_test.name)
            if (deployed_app is None):
                raise(Exception('Could not find app: ' + self.app_to_test.name))
            self.__deployed_app = deployed_app
        return self.__deployed_app


class HttpUtil:

    class HttpResponse:
        def __init__(self, response, error=None):
            if (error):
                self.body = error.reason
                self.status = error.code
            else:
                self.body = response.read().decode()
                self.status = response.status
            logging.info(self)

        @classmethod
        def error(cls, error):
            return cls(response=None, error=error)

        def __str__(self):
            if (len(self.body) > 100):
                body = self.body[:100] + '... (truncated)'
            else:
                body = self.body
            return 'HTTP status: {}, body: {}'.format(self.status, body)

    def get_request(self, url, access_token=None, additional_headers={}):
        logging.info('Performing get request to ' + url)
        req = urllib.request.Request(url, method='GET')
        self.__add_headers(req, access_token, additional_headers)
        return self.__execute(req)

    def post_request(self, url, data=None, access_token=None, additional_headers={}):
        logging.info('Performing post request to ' + url)
        req = urllib.request.Request(url, data=data, method='POST')
        self.__add_headers(req, access_token, additional_headers)
        return self.__execute(req)

    def get_access_token(self, xsuaa_service_url, clientid, clientsecret, grant_type, username=None, password=None):
        post_req_body = urllib.parse.urlencode({'client_id': clientid,
                                                'client_secret': clientsecret,
                                                'grant_type': grant_type,
                                                'response_type': 'token',
                                                'username': username,
                                                'password': password}).encode()
        url = xsuaa_service_url + '/oauth/token'
        resp = HttpUtil().post_request(url, data=post_req_body)
        return json.loads(resp.body).get('access_token')

    def __add_headers(self, req, access_token, additional_headers):
        if (access_token is not None):
            req.add_header('Authorization', 'Bearer ' + access_token)
        for header_key in additional_headers:
            req.add_header(header_key, additional_headers[header_key])

    def __execute(self, req):
        try:
            res = urllib.request.urlopen(req)
            return HttpUtil.HttpResponse(response=res)
        except urllib.error.HTTPError as error:
            return HttpUtil.HttpResponse.error(error=error)


class ApiAccessService:

    def __init__(self, xsuaa_service_url, xsuaa_api_url, name='api-access-service'):
        self.name = name
        self.service_key_name = self.name + '-sk'
        self.xsuaa_api_url = xsuaa_api_url
        self.xsuaa_service_url = xsuaa_service_url
        self.http_util = HttpUtil()
        subprocess.run(['cf', 'create-service', 'xsuaa', 'apiaccess', name])
        subprocess.run(['cf', 'create-service-key', name,
                        self.service_key_name])
        service_key_output = subprocess.run(
            ['cf', 'service-key', name, self.service_key_name], capture_output=True)
        lines = service_key_output.stdout.decode().split('\n')
        self.data = json.loads(''.join(lines[1:]))

    def delete(self):
        subprocess.run(['cf', 'delete-service-key', '-f',
                        self.name, self.service_key_name])
        subprocess.run(['cf', 'delete-service', '-f', self.name])

    def get_user_by_username(self, username):
        url = '{}/Users'.format(self.xsuaa_api_url)
        res = self.http_util.get_request(
            url, access_token=self.__get_access_token())
        users = json.loads(res.body).get('resources')
        for user in users:
            if (user.get('userName') == username):
                return user

    def add_user_to_group(self, user_id, group_id):
        post_req_body = json.dumps(
            {'value': user_id, 'origin': 'ldap', 'type': 'USER'}).encode()
        url = '{}/Groups/{}/members'.format(self.xsuaa_api_url, group_id)
        return self.http_util.post_request(url, data=post_req_body,
                                           access_token=self.__get_access_token(),
                                           additional_headers={'Content-Type': 'application/json'})

    def __get_access_token(self):
        return self.http_util.get_access_token(
            xsuaa_service_url=self.xsuaa_service_url,
            clientid=self.data.get('clientid'),
            clientsecret=self.data.get('clientsecret'),
            grant_type='client_credentials')

    def __str__(self):
        formatted_data = json.dumps(self.data, indent=2)
        return 'Name: {}, Service-Key-Name: {}, Data: {}'.format(
            self.name, self.service_key_name, formatted_data)


class CFApps:
    def __init__(self):
        token = subprocess.run(['cf', 'oauth-token'], capture_output=True)
        target = subprocess.run(['cf', 'target'], capture_output=True)
        self.bearer_token = token.stdout.strip().decode()
        [self.cf_api_endpoint, self.user_id] = self.__parse_target_output(
            target.stdout.decode())

    def app_by_name(self, app_name):
        apps = self.__retrieve_apps()
        for app in apps:
            if (app is not None and app.get('name') == app_name):
                vcap_services = self.__vcap_services_by_guid(app.get('guid'))
                return DeployedApp(vcap_services)

    def __get_with_token(self, url):
        res = HttpUtil().get_request(url, additional_headers={
            'Authorization': self.bearer_token})
        return json.loads(res.body)

    def __retrieve_apps(self):
        return self.__get_with_token(self.cf_api_endpoint + '/apps').get('resources')

    def __vcap_services_by_guid(self, guid):
        env = self.__get_with_token(
            self.cf_api_endpoint + '/apps/{}/env'.format(guid))
        return env.get('system_env_json').get('VCAP_SERVICES')

    def __parse_target_output(self, target_output):
        api_endpoint_match = re.search(r'api endpoint:(.*)', target_output)
        user_id_match = re.search(r'user:(.*)', target_output)
        api_endpoint = api_endpoint_match.group(1)
        user_id = user_id_match.group(1)
        return [api_endpoint.strip() + '/v3', user_id.strip()]


class VarsParser:

    """
        This class parses the content of the vars.yml file in the samples directory, e.g:
    >>> vars = VarsParser('# change to another value, e.g. your User ID\\nID: X0000000\\n# Choose cfapps.eu10.hana.ondemand.com for the EU10 landscape, cfapps.us10.hana.ondemand.com for US10\\nLANDSCAPE_APPS_DOMAIN: cfapps.sap.hana.ondemand.com\\n#LANDSCAPE_APPS_DOMAIN: api.cf.eu10.hana.ondemand.com\\n')
    >>> vars.user_id
    'X0000000'
    >>> vars.landscape_apps_domain
    'cfapps.sap.hana.ondemand.com'

    """

    def __init__(self, vars_file_content):
        self.vars_file_content = self.__strip_comments(vars_file_content)

    @property
    def user_id(self):
        id_match = re.search(r'ID:(.*)', self.vars_file_content)
        return id_match.group(1).strip()

    @property
    def landscape_apps_domain(self):
        landscape_match = re.search(r'LANDSCAPE_APPS_DOMAIN:(.*)',
                                    self.vars_file_content)
        return landscape_match.group(1).strip()

    def __strip_comments(self, content):
        result = ''
        for line in content.split('\n'):
            commented_line = re.search(r'\w*#', line)
            if (commented_line is None):
                result += line + '\n'
        return result


class DeployedApp:
    """
        This class parses VCAP_SERVICES (as dictionary) and supplies its content, e.g.:
    >>> vcap_services = {'xsuaa': [{'label': 'xsuaa', 'provider': None, 'plan': 'application', 'name': 'xsuaa-java-security', 'tags': ['xsuaa'], 'instance_name': 'xsuaa-java-security', 'binding_name': None, 'credentials': {'tenantmode': 'dedicated', 'sburl': 'https://internal-xsuaa.authentication.sap.hana.ondemand.com', 'clientid': 'sb-java-security-usage!t1785', 'xsappname': 'java-security-usage!t1785', 'clientsecret': 'b1GhPeHArXQCimhsCiwOMzT8wOU=', 'url': 'https://saschatest01.authentication.sap.hana.ondemand.com', 'uaadomain': 'authentication.sap.hana.ondemand.com', 'verificationkey': '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/jN5v1mp/TVn9nTQoYVIUfCsUDHa3Upr5tDZC7mzlTrN2PnwruzyS7w1Jd+StqwW4/vn87ua2YlZzU8Ob0jR4lbOPCKaHIi0kyNtJXQvQ7LZPG8epQLbx0IIP/WLVVVtB8bL5OWuHma3pUnibbmATtbOh5LksQ2zLMngEjUF52JQyzTpjoQkahp0BNe/drlAqO253keiY63FL6belKjJGmSqdnotSXxB2ym+HQ0ShaNvTFLEvi2+ObkyjGWgFpQaoCcGq0KX0y0mPzOvdFsNT+rBFdkHiK+Jl638Sbim1z9fItFbH9hiVwY37R9rLtH1YKi3PuATMjf/DJ7mUluDQIDAQAB-----END PUBLIC KEY-----', 'apiurl': 'https://api.authentication.sap.hana.ondemand.com', 'identityzone': 'saschatest01', 'identityzoneid': '54d48a27-0ff4-42b8-b39e-a2b6df64d78a', 'tenantid': '54d48a27-0ff4-42b8-b39e-a2b6df64d78a'}, 'syslog_drain_url': None, 'volume_mounts': []}]}
    >>> app = DeployedApp(vcap_services)
    >>> app.get_credentials_property('clientsecret')
    'b1GhPeHArXQCimhsCiwOMzT8wOU='
    >>> app.clientsecret
    'b1GhPeHArXQCimhsCiwOMzT8wOU='

    """

    def __init__(self, vcap_services):
        self.vcap_services = vcap_services
        self.xsuaa_properties = self.vcap_services.get('xsuaa')[0]

    @property
    def xsuaa_api_url(self):
        return self.get_credentials_property('apiurl')

    @property
    def xsuaa_service_url(self):
        return self.get_credentials_property('url')

    @property
    def clientid(self):
        return self.get_credentials_property('clientid')

    @property
    def clientsecret(self):
        return self.get_credentials_property('clientsecret')

    def get_credentials_property(self, property_name):
        return self.xsuaa_properties.get('credentials').get(property_name)

    def __str__(self):
        return json.dumps(self.vcap_services, indent=2)


class CFApp:
    def __init__(self, name, xsuaa_service_name, app_router_name=None):
        self.name = name
        self.xsuaa_service_name = xsuaa_service_name
        self.app_router_name = app_router_name

    @property
    def working_dir(self):
        return './' + self.name

    def deploy(self):
        subprocess.run(['cf', 'create-service', 'xsuaa', 'application',
                        self.xsuaa_service_name, '-c', 'xs-security.json'], cwd=self.working_dir)
        subprocess.run(['mvn', 'clean', 'verify'], cwd=self.working_dir)
        subprocess.run(['cf', 'push', '--vars-file',
                        '../vars.yml'], cwd=self.working_dir)

    def delete(self):
        subprocess.run(['cf',  'delete', '-f', self.name])
        if (self.app_router_name is not None):
            subprocess.run(['cf',  'delete',  '-f', self.app_router_name])
        subprocess.run(
            ['cf',  'delete-service', '-f', self.xsuaa_service_name])

    def __str__(self):
        return 'Name: {}, Xsuaa-Service-Name: {}, App-Router-Name: {}'.format(
            self.name, self.xsuaa_service_name, self.app_router_name)


apps = [
    CFApp(name='java-security-usage', xsuaa_service_name='xsuaa-java-security'),
    CFApp(name='java-tokenclient-usage',
          xsuaa_service_name='xsuaa-token-client'),
    CFApp(name='spring-security-basic-auth', xsuaa_service_name='xsuaa-basic'),
    CFApp(name='spring-webflux-security-xsuaa-usage', xsuaa_service_name='xsuaa-webflux',
          app_router_name='approuter-spring-webflux-security-xsuaa-usage')
]


def is_logged_off():
    target = subprocess.run(['cf', 'target'], capture_output=True)
    return not target or target.stdout.decode().startswith('FAILED')


if __name__ == '__main__':
    if (is_logged_off()):
        print('To run this script you must be logged into CF via "cf login"')
        print('Also make sure to change settings in vars.yml')
    else:
        import doctest
        doctest.testmod()
        unittest.main()
