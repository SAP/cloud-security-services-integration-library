#!/usr/bin/env python3
import subprocess
import urllib.request
import urllib.parse
import json
import unittest
import logging
import sys
import os
from getpass import getpass

cf_api = 'https://api.cf.sap.hana.ondemand.com/v3'
uaa_api = 'https://saschatest01.authentication.sap.hana.ondemand.com'
xsuaa_api = 'https://api.authentication.sap.hana.ondemand.com'

username = os.getenv("CFUSER")
password = os.getenv("CFPASSWORD")

if (username is None):
    print('Type username: ')
    username = sys.stdin.readline()
if (password is None):
    password = getpass()

logging.basicConfig(level=logging.INFO)


class TestJavaSecurity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.apiAccess = ApiAccessServiceKey('asdf')
        cls.app = CFApp(name="java-security-usage", xsuaa_service_name="xsuaa-java-security",
                        endpoints=[Endpoint(path='hello-java-security', required_roles=['JAVA_SECURITY_SAMPLE_Viewer'])])
        cls.app.deploy()
        cfUtil = CFUtil()
        app = cfUtil.app_by_name(cls.app.name)
        cls.user_id = cls.apiAccess.get_user_by_username(username).get('id')
        cls.clientid = app.get_credentials_property('clientid')
        cls.clientsecret = app.get_credentials_property('clientsecret')

    @classmethod
    def tearDownClass(cls):
        cls.app.delete()
        cls.apiAccess.delete()

    def test_endpoint(self):
        for endpoint in TestJavaSecurity.app.endpoints:
            for role in endpoint.required_roles:
                print('Adding user to role: ', role)
                TestJavaSecurity.apiAccess.add_user_to_group(
                    TestJavaSecurity.user_id, role)
            user_access_token = get_access_token(
                TestJavaSecurity.clientid, TestJavaSecurity.clientsecret, 'password', username=username, password=password)
            url = 'https://{}-{}.cfapps.sap.hana.ondemand.com/{}'.format(
                apps[0].name, 'C5295400', endpoint.path)
            body = HttpUtil().get_request(url, access_token=user_access_token).body()
            logging.info(body)
            self.assertEqual(
                body, "You ('{}') can access the application with the following scopes: '[openid, java-security-usage!t1785.Read]'.".format(username))


class HttpUtil:

    class HttpResponse:

        def __init__(self, response, error=None):
            self.response = response
            self.err = error
            logging.info(self)

        @classmethod
        def error(cls, error):
            return cls(None, error=error)

        def status(self):
            return self.response.status

        def body(self):
            return self.response.read().decode()

        def __str__(self):
            if (self.response is None):
                return "HTTP status: {}, {}".format(self.err.status, self.err.reason)
            else:
                return "HTTP response status: " + str(self.response.status)

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

    def __add_headers(self, req, access_token, additional_headers):
        if (access_token is not None):
            req.add_header('Authorization', 'Bearer ' + access_token)
        for header_key in additional_headers:
            req.add_header(header_key, additional_headers[header_key])

    def __execute(self, req):
        try:
            res = urllib.request.urlopen(req)
            return HttpUtil.HttpResponse(res)
        except urllib.error.HTTPError as error:
            return HttpUtil.HttpResponse.error(error)


def get_access_token(clientid, clientsecret, grant_type, username=None, password=None):
    post_req_body = urllib.parse.urlencode({'client_id': clientid,
                                            'client_secret': clientsecret,
                                            'grant_type': grant_type,
                                            'response_type': 'token',
                                            'username': username,
                                            'password': password}).encode()
    url = uaa_api + '/oauth/token'
    resp = HttpUtil().post_request(url, data=post_req_body)
    return json.loads(resp.body()).get("access_token")


class ApiAccessServiceKey:

    def __init__(self, name):
        self.name = name
        self.service_key_name = self.name + '-sk'
        subprocess.run(['cf', 'create-service', 'xsuaa', 'apiaccess', name])
        subprocess.run(['cf', 'create-service-key', name,
                        self.service_key_name])
        service_key_output = subprocess.run(
            ['cf', 'service-key', name, self.service_key_name], capture_output=True)
        lines = service_key_output.stdout.decode().split('\n')
        self.data = json.loads("".join(lines[1:]))

    def delete(self):
        subprocess.run(['cf', 'delete-service-key', '-f',
                        self.name, self.service_key_name])
        subprocess.run(['cf', 'delete-service', '-f', self.name])

    def get_user_by_username(self, username):
        url = "{}/Users".format(xsuaa_api)
        res = HttpUtil().get_request(url, access_token=self.__get_access_token())
        users = json.loads(res.body()).get("resources")
        for user in users:
            if (user.get("userName") == username):
                return user

    def add_user_to_group(self, user_id, group_id):
        post_req_body = json.dumps(
            {'value': user_id, 'origin': 'ldap', 'type': 'USER'}).encode()
        url = "{}/Groups/{}/members".format(xsuaa_api, group_id)
        return HttpUtil().post_request(url, data=post_req_body,
                                       access_token=self.__get_access_token(),
                                       additional_headers={'Content-Type': 'application/json'})

    def __get_access_token(self):
        return get_access_token(self.__get_clientid(), self.__get_clientcredentials(), "client_credentials")

    def __get_clientid(self):
        return self.data.get('clientid')

    def __get_clientcredentials(self):
        return self.data.get('clientsecret')

    def __str__(self):
        formatted_data = json.dumps(self.data, indent=2)
        return 'Name: {}, Service-Key-Name: {}, Data: {}'.format(self.name, self.service_key_name, formatted_data)


class CFUtil:
    def __init__(self):
        token = subprocess.run(['cf', 'oauth-token'], capture_output=True)
        self.bearer_token = token.stdout.strip().decode()
        self.apps = self.__retrieve_apps()

    def app_by_name(self, app_name):
        for app in self.apps:
            if (app is not None and app.get("name") == app_name):
                vcap_services = self.__vcap_services_by_guid(app.get('guid'))
                return DeployedApp(vcap_services)

    def __get_with_token(self, url):
        res = HttpUtil().get_request(url, additional_headers={
            'Authorization': self.bearer_token})
        return json.loads(res.body())

    def __retrieve_apps(self):
        return self.__get_with_token(cf_api + '/apps').get('resources')

    def __vcap_services_by_guid(self, guid):
        env = self.__get_with_token(cf_api + '/apps/{}/env'.format(guid))
        return env.get('system_env_json').get('VCAP_SERVICES')


class DeployedApp:
    """
        This class parses VCAP_SERVICES (as dictionary) and supplies its content, e.g.:
    >>> vcap_services = {'xsuaa': [{'label': 'xsuaa', 'provider': None, 'plan': 'application', 'name': 'xsuaa-java-security', 'tags': ['xsuaa'], 'instance_name': 'xsuaa-java-security', 'binding_name': None, 'credentials': {'tenantmode': 'dedicated', 'sburl': 'https://internal-xsuaa.authentication.sap.hana.ondemand.com', 'clientid': 'sb-java-security-usage!t1785', 'xsappname': 'java-security-usage!t1785', 'clientsecret': 'b1GhPeHArXQCimhsCiwOMzT8wOU=', 'url': 'https://saschatest01.authentication.sap.hana.ondemand.com', 'uaadomain': 'authentication.sap.hana.ondemand.com', 'verificationkey': '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/jN5v1mp/TVn9nTQoYVIUfCsUDHa3Upr5tDZC7mzlTrN2PnwruzyS7w1Jd+StqwW4/vn87ua2YlZzU8Ob0jR4lbOPCKaHIi0kyNtJXQvQ7LZPG8epQLbx0IIP/WLVVVtB8bL5OWuHma3pUnibbmATtbOh5LksQ2zLMngEjUF52JQyzTpjoQkahp0BNe/drlAqO253keiY63FL6belKjJGmSqdnotSXxB2ym+HQ0ShaNvTFLEvi2+ObkyjGWgFpQaoCcGq0KX0y0mPzOvdFsNT+rBFdkHiK+Jl638Sbim1z9fItFbH9hiVwY37R9rLtH1YKi3PuATMjf/DJ7mUluDQIDAQAB-----END PUBLIC KEY-----', 'apiurl': 'https://api.authentication.sap.hana.ondemand.com', 'identityzone': 'saschatest01', 'identityzoneid': '54d48a27-0ff4-42b8-b39e-a2b6df64d78a', 'tenantid': '54d48a27-0ff4-42b8-b39e-a2b6df64d78a'}, 'syslog_drain_url': None, 'volume_mounts': []}]}
    >>> app = DeployedApp(vcap_services)
    >>> app.get_name()
    'xsuaa-java-security'
    >>> app.get_credentials_property('clientsecret')
    'b1GhPeHArXQCimhsCiwOMzT8wOU='
    """

    def __init__(self, vcap_services):
        self.vcap_services = vcap_services
        self.xsuaa_properties = self.vcap_services.get('xsuaa')[0]

    def get_credentials_property(self, property_name):
        return self.xsuaa_properties.get('credentials').get(property_name)

    def get_name(self):
        return self.xsuaa_properties.get('name')

    def __str__(self):
        return json.dumps(self.vcap_services, indent=2)


class Endpoint():
    def __init__(self, path='/', required_roles=[]):
        self.path = path
        self.required_roles = required_roles

    def __str__(self):
        return 'Path: {}\nRoles: {}'.format(self.path, ', '.join(self.required_roles))


class CFApp:
    def __init__(self, name, xsuaa_service_name, endpoints=[], app_router_name=None):
        self.name = name
        self.xsuaa_service_name = xsuaa_service_name
        self.app_router_name = app_router_name
        self.endpoints = endpoints

    def working_dir(self):
        return './' + self.name

    def deploy(self):
        subprocess.run(['cf', 'create-service', 'xsuaa', 'application',
                        self.xsuaa_service_name, '-c', 'xs-security.json'], cwd=self.working_dir())
        subprocess.run(['mvn', 'clean', 'verify'], cwd=self.working_dir())
        subprocess.run(['cf', 'push', '--vars-file',
                        '../vars.yml'], cwd=self.working_dir())

    def delete(self):
        subprocess.run(['cf',  'delete', '-f', self.name])
        subprocess.run(
            ['cf',  'delete-service', '-f', self.xsuaa_service_name])
        if (self.app_router_name != None):
            subprocess.run(['cf',  'delete',  '-f', self.app_router_name])

    def __str__(self):
        'Name: {}, Xsuaa-Service-Name: {}, App-Router-Name: {}, End-Points: {}'.format(
            self.name, self.xsuaa_service_name, self.app_router_name, ', '.join(self.endpoints))


apps = [
    CFApp(name="java-security-usage", xsuaa_service_name="xsuaa-java-security",
          endpoints=[Endpoint(path='hello-java-security', required_roles=['JAVA_SECURITY_SAMPLE_Viewer'])]),
    CFApp(name="java-tokenclient-usage",
          xsuaa_service_name="xsuaa-token-client"),
    CFApp(name="sap-java-buildpack-api-usage",
          xsuaa_service_name="xsuaa-buildpack"),
    CFApp(name="spring-security-basic-auth", xsuaa_service_name="xsuaa-basic"),
    CFApp(name="spring-security-xsuaa-usage", xsuaa_service_name="xsuaa-authentication",
          app_router_name="approuter-spring-security-xsuaa-usage"),
    CFApp(name="spring-webflux-security-xsuaa-usage", xsuaa_service_name="xsuaa-webflux",
          app_router_name="approuter-spring-webflux-security-xsuaa-usage")
]

if __name__ == "__main__":
    import doctest
    doctest.testmod()
    unittest.main()
