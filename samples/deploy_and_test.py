#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
# SPDX-License-Identifier: Apache-2.0
import abc
import distutils
import http
import json
import logging
import os
import re
import ssl
import subprocess
import time
import unittest
import urllib.request
from base64 import b64encode
from getpass import getpass
from urllib.error import HTTPError
from urllib.parse import urlencode

# Usage information
# To run this script you must be logged into CF via 'cf login' Also make sure
# to change settings in vars.yml to your needs.  This script deploys sample
# apps and fires post request against their endpoints.  For some samples it
# needs to create a password token for which you need to provide your password
# (same as you would use for 'cf login'). You can do this by either supplying
# it via the system environment variable 'CFPASSWORD' or by typing when the
# script prompts for the password.  The same goes for the username with the
# variable 'CFUSER'.
# For IAS tests where manual user interaction is required to add user roles in SCP Cockpit,
# system environment variable USER_INPUT_ENABLED needs to be set to true
# by setting the value to 'y', 'yes', 't', 'true', 'on', '1' if it's disabled user input won't be requested.

# Dependencies
# The script depends on python3 and the cloud foundry command line tool 'cf'.

# Running the script
# If the script is made executable, it can be started with cd
# It can also be started like so: python3 ./deploy_and_test.py
# By default it will run all unit tests.
# It is also possible to run specific test classes (if no token is required):
# python3 -m unittest deploy_and_test.TestJavaSecurity.test_hello_java_security
# This would only the run the test called 'test_hello_java_security'
# inside the test class 'TestJavaSecurity' inside the deploy_and_test.py file.

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - [%(module)s.%(funcName)s: L%(lineno)d]: %(message)s')
cf_logs = open('cf-logs.log', 'w')
java_logs = open('java-logs.log', 'w')
RUN_TESTS = "Running '{}' tests"
RUN_TEST = "Running '{}' test"
EXPECT_200 = "Expected HTTP status 200"
EXPECT_401 = "Expected HTTP status 401"
EXPECT_403 = "Expected HTTP status 403"


class Credentials:
    def __init__(self):
        self.username = self.__get_env_variable('CFUSER', lambda: input("Username: "))
        self.password = self.__get_env_variable('CFPASSWORD', lambda: getpass())

    def __get_env_variable(self, env_variable_name, prompt_function):
        value = os.getenv(env_variable_name)
        if value is None:
            value = prompt_function()
        return value


credentials = Credentials()


# Abstract base class for sample app tests classes 
class SampleTest(abc.ABC, unittest.TestCase):
    cf_app = None
    api_access = None
    ias_access = None

    @classmethod
    @abc.abstractmethod
    def get_app(cls):
        """Should return the sample app that should be tested """
        cls.skipTest('Dont run abstract base class')
        return cls.cf_app

    @classmethod
    def setUpClass(cls):
        vars_file = open('./vars.yml')
        cls.vars_parser = VarsParser(vars_file.read())
        vars_file.close()
        cls.cf_apps = CFApps()
        cls.__deployed_app = None
        cls.get_app(cls).deploy()
        cls.credentials = credentials
        time.sleep(2)  # waiting for deployed apps to be available

    @classmethod
    def tearDownClass(cls):
        cls.cf_app.delete()
        if cls.api_access is not None:
            cls.api_access.delete()
        if cls.ias_access is not None:
            cls.ias_access.delete()

    def add_user_to_role(self, role):
        logging.info('Assigning role collection {} for user {}'.format(role, self.credentials.username))
        user = self.__get_api_access().get_user_by_username(self.credentials.username)
        user_id = user.get('id')
        resp = self.__get_api_access().add_user_to_group(user_id, role)
        if not resp.is_ok and resp.status != 409:  # 409 is returned when role is already assigned to the user
            logging.error(
                "Could not set '{}' role to user '{}'. Error: {} - {}".format(role, user.get('userName'), resp.status,
                                                                              resp.body))
            exit()

    def perform_get_request(self, path, username=None, password=None):
        if username is not None and password is not None:
            authorization_value = b64encode(
                bytes(username + ':' + password + self.__get_2factor_auth_code(), 'utf-8')).decode("ascii")
            return self.__perform_get_request(path=path,
                                              additional_headers={'Authorization': 'Basic ' + authorization_value})
        return self.__perform_get_request(path=path)

    def perform_get_request_with_token(self, path, additional_headers={}):
        access_token = self.get_token().get('access_token')
        if access_token is None:
            logging.error("Cannot continue without access token")
            exit()
        return self.__perform_get_request(path=path, access_token=access_token, additional_headers=additional_headers)

    def perform_get_request_with_ias_token(self, path, id_token, additional_headers={}):
        return self.__perform_get_request(path=path, access_token=id_token, additional_headers=additional_headers)

    def get_deployed_app(self):
        if self.__deployed_app is None:
            deployed_app = self.cf_apps.app_by_name(self.cf_app.name)
            if deployed_app is None:
                logging.error('Could not find app: ' + self.cf_app.name)
                exit()
            self.__deployed_app = deployed_app
        return self.__deployed_app

    def get_token(self):
        deployed_app = self.get_deployed_app()
        logging.info('GET xsuaa token to {} for user {} (credential-type = {}, clientid = {}, clientsecret = {})'.format(deployed_app.xsuaa_service_url,
                                                                         self.credentials.username,
                                                                         deployed_app.credential_type,
                                                                         deployed_app.clientid,
                                                                         deployed_app.clientsecret))
        if deployed_app.credential_type == 'x509':
            body = HttpUtil.encode_request_body(self,
                                                clientid=deployed_app.clientid,
                                                grant_type='password',
                                                username=self.credentials.username,
                                                password=self.credentials.password + self.__get_2factor_auth_code())
            return HttpUtil.post_request_x509(self,
                                              url=deployed_app.xsuaa_cert_url,
                                              url_path='/oauth/token',
                                              payload=body,
                                              certificate=deployed_app.certificate,
                                              key=deployed_app.key)
        else:
            return HttpUtil().get_token(
                xsuaa_service_url=deployed_app.xsuaa_service_url,
                clientid=deployed_app.clientid,
                clientsecret=deployed_app.clientsecret,
                grant_type='password',
                username=self.credentials.username,
                password=self.credentials.password + self.__get_2factor_auth_code())

    def get_id_token(self):
        deployed_app = self.get_deployed_app()

        logging.info(
            'GET id token to {} for user {} ({}, {})'.format(deployed_app.ias_service_url, self.credentials.username,
                                                             deployed_app.ias_clientid, deployed_app.ias_clientsecret))
        id_token = HttpUtil().get_id_token(
            ias_service_url=deployed_app.ias_service_url,
            clientid=deployed_app.ias_clientid,
            clientsecret="" if deployed_app.ias_clientsecret is None else deployed_app.ias_clientsecret,
            certificate=deployed_app.ias_certificate,
            key=deployed_app.ias_key,
            grant_type='password',
            username=self.credentials.username,
            password=self.credentials.password).get('id_token')

        if id_token is None:
            logging.error("Cannot continue without id token")
            exit()
        return id_token

    @classmethod
    def __get_api_access(cls):
        if cls.api_access is None:
            deployed_app = cls.get_deployed_app(cls)
            cls.api_access = ApiAccessService(
                xsuaa_service_url=deployed_app.xsuaa_service_url,
                xsuaa_api_url=deployed_app.xsuaa_api_url)
        return cls.api_access

    @classmethod
    def get_ias_access(cls, ias_name):
        if cls.ias_access is None:
            cls.ias_access = IasAccess(ias_name=ias_name)
        return cls.ias_access

    def __perform_get_request(self, path, access_token=None, additional_headers={}):
        url = 'https://{}-{}.{}{}'.format(
            self.cf_app.name,
            self.vars_parser.user_id,
            self.vars_parser.landscape_apps_domain,
            path)
        logging.info('GET request to {} {}'
                     .format(url, 'with access token: ' + access_token if access_token else 'without access token'))
        resp = HttpUtil().get_request(url, access_token=access_token, additional_headers=additional_headers)
        logging.info('Response: ' + str(resp))
        return resp

    def __get_2factor_auth_code(self):
        auth_code = ""
        if os.getenv('ENABLE_2_FACTOR') is not None:
            auth_code = input("2-Factor Authenticator Code: ") or ""
        return auth_code

    def prompt_user_role_assignment(self):
        usr_input_enabled = os.getenv("USER_INPUT_ENABLED")
        if usr_input_enabled and bool(distutils.util.strtobool(usr_input_enabled)) is True:
            input("Can't add user Role Collection to the custom IAS origin. \n"
                  "Please add the role 'Viewer' to user {} in SCP Cockpit manually. \n"
                  "Once done press enter to proceed with the test."
                  .format(self.credentials.username))
            return True
        return False


class TestTokenClient(SampleTest):

    def get_app(self):
        logging.info(RUN_TESTS.format("TokenClientUsage"))
        self.cf_app = CFApp(name='java-tokenclient-usage', xsuaa_service_name='xsuaa-token-client')
        return self.cf_app

    def test_hello_token_client(self):
        logging.info(RUN_TEST.format("TestTokenClient.test_hello_token_client"))
        response = self.perform_get_request('/hello-token-client')
        self.assertEqual(200, response.status, EXPECT_200)
        body = response.body
        self.assertIsNotNone(body)
        self.assertRegex(body, "Access-Token: ")
        self.assertRegex(body, "Access-Token-Payload: ")
        self.assertRegex(body, "Expired-At: ")


class TestJavaSecurity(SampleTest):

    def get_app(self):
        logging.info(RUN_TESTS.format("JavaSecurityUsage"))
        self.cf_app = CFApp(name='java-security-usage', xsuaa_service_name='xsuaa-java-security')
        return self.cf_app

    def test_health(self):
        logging.info(RUN_TEST.format("TestJavaSecurity.test_health"))
        resp = self.perform_get_request('/health')
        self.assertEqual(200, resp.status, EXPECT_200)

    def test_hello_java_security(self):
        logging.info(RUN_TEST.format("TestJavaSecurity.test_hello_java_security"))
        resp = self.perform_get_request('/hello-java-security')
        self.assertEqual(401, resp.status, EXPECT_401)

        resp = self.perform_get_request_with_token('/hello-java-security')
        self.assertEqual(200, resp.status, EXPECT_200)

        self.assertIsNotNone(resp.body)
        self.assertRegex(resp.body, self.credentials.username,
                         "Did not find username '{}' in response body: {}".format(self.credentials.username, resp.body))

    def test_hello_java_security_authz(self):
        logging.info(RUN_TEST.format("TestJavaSecurity.test_hello_java_security_authz"))

        resp = self.perform_get_request('/hello-java-security-authz')
        self.assertEqual(401, resp.status, EXPECT_401)

        resp = self.perform_get_request_with_token('/hello-java-security-authz')
        self.assertEqual(403, resp.status, EXPECT_403)

        self.add_user_to_role('JAVA_SECURITY_SAMPLE_Viewer')
        resp = self.perform_get_request_with_token('/hello-java-security-authz')
        self.assertEqual(200, resp.status, EXPECT_200)


class TestSpringSecurityHybrid(SampleTest):

    def get_app(self):
        logging.info(RUN_TESTS.format("SpringSecurityHybrid"))
        self.cf_app = CFApp(name='spring-security-hybrid-usage', xsuaa_service_name='xsuaa-authn', identity_service_name='ias-authn')
        return self.cf_app

    def test_sayHello_xsuaa(self):
        resp = self.perform_get_request('/sayHello')
        self.assertEqual(401, resp.status, EXPECT_401)

        resp = self.perform_get_request_with_token('/sayHello')
        self.assertEqual(403, resp.status, EXPECT_403)

        self.add_user_to_role('XSUAA-Viewer')
        resp = self.perform_get_request_with_token('/sayHello')
        self.assertEqual(200, resp.status, EXPECT_200)
        clientid = self.get_deployed_app().get_credentials_property('clientid')
        self.assertRegex(resp.body, clientid, 'Expected to find clientid in response')

        resp = self.perform_get_request_with_token('/method')
        self.assertEqual(200, resp.status, EXPECT_200)
        self.assertRegex(resp.body, 'You got the sensitive data for zone', 'Expected another response.')

    def test_sayHello_ias(self):
        resp = self.perform_get_request_with_ias_token('/sayHello', self.get_id_token())
        self.assertEqual(403, resp.status, EXPECT_403)


class TestJavaSecurityIas(SampleTest):

    def get_app(self):
        logging.info(RUN_TESTS.format("JavaSecurityIas"))
        self.cf_app = CFApp(name='java-security-usage-ias', identity_service_name='ias-java-security')
        return self.cf_app

    def test_sayHello_ias(self):
        resp = self.perform_get_request('/hello-java-security-ias')
        self.assertEqual(401, resp.status, EXPECT_401)

        resp = self.perform_get_request_with_ias_token('/hello-java-security-ias', self.get_id_token())
        self.assertEqual(200, resp.status, EXPECT_200)
        self.assertIsNotNone(resp.body)
        self.assertRegex(resp.body, "are authenticated and can access the application.")


class TestSpringXsuaa(SampleTest):

    def get_app(self):
        logging.info(RUN_TESTS.format("SpringSecurityUsageMtls"))
        self.cf_app = CFApp(name='spring-security-xsuaa-usage', xsuaa_service_name='xsuaa-authentication',
                            app_router_name='approuter-spring-security-xsuaa-usage')
        return self.cf_app

    def test_sayHello(self):
        logging.info(RUN_TEST.format("TestSpringSecurity.test_sayHello'"))
        resp = self.perform_get_request('/v1/sayHello')
        self.assertEqual(resp.status, 401, EXPECT_401)

        resp = self.perform_get_request_with_token('/v1/sayHello')
        self.assertEqual(resp.status, 403, EXPECT_403)

        self.add_user_to_role('Viewer')
        resp = self.perform_get_request_with_token('/v1/sayHello')
        self.assertEqual(resp.status, 200, EXPECT_200)
        xsappname = self.get_deployed_app().get_credentials_property('xsappname')
        self.assertRegex(resp.body, xsappname, 'Expected to find xsappname in response')

    def test_tokenFlows(self):
        logging.info(RUN_TEST.format("TestSpringSecurity.test_tokenFlows"))
        self.add_user_to_role('Viewer')
        resp = self.perform_get_request_with_token('/v2/sayHello')
        self.assertEqual(resp.status, 200, EXPECT_200)

        resp = self.perform_get_request_with_token('/v3/requestClientCredentialsToken')
        self.assertEqual(resp.status, 200, EXPECT_200)

        resp = self.perform_get_request_with_token('/v3/requestJwtBearerToken')
        self.assertEqual(resp.status, 200, EXPECT_200)

        token = self.get_token()
        path_with_refresh_token = '/v3/requestRefreshToken/' + token.get('refresh_token')
        resp = self.perform_get_request_with_token(path_with_refresh_token)
        self.assertEqual(resp.status, 200, EXPECT_200)

    def test_sayHello_ias(self):
        ias_service = self.get_ias_access("ias-spring-sec")

        resp = self.perform_get_request_with_ias_token('/v1/sayHello', ias_service.fetch_ias_token(self))
        self.assertEqual(403, resp.status, EXPECT_403)
        if self.prompt_user_role_assignment():
            resp = self.perform_get_request_with_ias_token('/v1/sayHello', ias_service.fetch_ias_token(self))
            if resp.status != 200:
                logging.warning("In case after adding role collection, user is still not authorized. "
                                "Check in IAS admin panel that the application's '{}' Subject Name Identifier is set to email. "
                                "Bug: NGPBUG-139441 "
                                .format(ias_service.ias_service_name))
            self.assertEqual(200, resp.status, EXPECT_200)
            xsappname = self.get_deployed_app().get_credentials_property('xsappname')
            self.assertRegex(resp.body, xsappname, 'Expected to find xsappname in response')
        else:
            logging.warning('test_sayHello_ias was skipped. To run test enable environment variable USER_INPUT_ENABLED=true')

    def test_open_endpoint(self):
        resp = self.perform_get_request('/health')
        self.assertEqual(200, resp.status, EXPECT_200)


class TestSpringXsuaaNonMtls(SampleTest):

    def get_app(self):
        logging.info(RUN_TESTS.format("SpringSecurityUsageNonMtls"))
        self.cf_app = CFApp(name='spring-security-xsuaa-usage',
                            xsuaa_service_name='xsuaa-authentication',
                            app_router_name='approuter-spring-security-xsuaa-usage',
                            security_descriptor='xs-security-deprecated.json')
        return self.cf_app

    def test_tokenFlows(self):
        logging.info(RUN_TEST.format("TestSpringSecurity.test_tokenFlows"))
        self.add_user_to_role('Viewer')
        resp = self.perform_get_request_with_token('/v2/sayHello')
        self.assertEqual(200, resp.status, EXPECT_200)
        resp = self.perform_get_request_with_token('/v3/requestClientCredentialsToken')
        self.assertEqual(200, resp.status, EXPECT_200)
        resp = self.perform_get_request_with_token('/v3/requestUserToken')
        self.assertEqual(200, resp.status, EXPECT_200)
        token = self.get_token()
        path_with_refresh_token = '/v3/requestRefreshToken/' + token.get('refresh_token')
        resp = self.perform_get_request_with_token(path_with_refresh_token)
        self.assertEqual(200, resp.status, EXPECT_200)


class TestJavaBuildpackApi(SampleTest):

    def get_app(self):
        logging.info(RUN_TESTS.format("JavaBuildpackApiUsage"))
        self.cf_app = CFApp(name='sap-java-buildpack-api-usage',
                            xsuaa_service_name='xsuaa-buildpack',
                            app_router_name='approuter-sap-java-buildpack-api-usage')
        return self.cf_app

    def test_hello_token_servlet(self):
        logging.info(RUN_TEST.format("TestJavaBuildpackApiUsage.test_hello_token_servlet"))
        resp = self.perform_get_request('/hello-token')
        self.assertEqual(401, resp.status, EXPECT_401)

        resp = self.perform_get_request_with_token('/hello-token')
        self.assertEqual(403, resp.status, EXPECT_403)

        self.add_user_to_role('Buildpack_API_Viewer')
        resp = self.perform_get_request_with_token('/hello-token')
        self.assertEqual(200, resp.status, EXPECT_200)
        self.assertRegex(resp.body, self.credentials.username, 'Expected to find username in response')


class SpringSecurityBasicAuth(SampleTest):

    def get_app(self):
        logging.info(RUN_TESTS.format("SpringSecurityBasicAuthTest"))
        self.cf_app = CFApp(name='spring-security-basic-auth', xsuaa_service_name='xsuaa-basic')
        return self.cf_app

    def test_fetch_token(self):
        logging.info(RUN_TEST.format("SpringSecurityBasicAuthTest.test_fetch_token"))
        resp = self.perform_get_request('/fetchToken')
        self.assertEqual(401, resp.status, EXPECT_401)

        resp = self.perform_get_request('/fetchToken', username=self.credentials.username,
                                        password=self.credentials.password)
        self.assertEqual(403, resp.status, EXPECT_403)

    def test_fetch_token_status_ok(self):
        # app restart needed because tokens are cached in application
        self.cf_app.restart()
        logging.info(RUN_TEST.format("SpringSecurityBasicAuthTest.test_fetch_token_status_ok"))
        self.add_user_to_role('BASIC_AUTH_API_Viewer')
        resp = self.perform_get_request('/fetchToken', username=self.credentials.username,
                                        password=self.credentials.password)
        self.assertEqual(200, resp.status, EXPECT_200)
        self.assertRegex(resp.body, self.credentials.username, 'Expected to find username in response')


class SpringWebfluxSecurityXsuaa(SampleTest):

    def get_app(self):
        logging.info(RUN_TESTS.format("SpringWebfluxSecurityXsuaaUsage"))
        self.cf_app = CFApp(name='spring-webflux-security-xsuaa-usage',
                     xsuaa_service_name='xsuaa-webflux',
                     app_router_name='approuter-spring-webflux-security-xsuaa-usage')
        return self.cf_app

    def test_say_hello(self):
        logging.info(RUN_TEST.format("SpringWebfluxSecurityXsuaaUsage.test_say_hello"))
        resp = self.perform_get_request('/v1/sayHello')
        self.assertEqual(401, resp.status, EXPECT_401)

        resp = self.perform_get_request_with_token('/v1/sayHello')
        self.assertEqual(403, resp.status, EXPECT_403)

        self.add_user_to_role('Webflux_API_Viewer')
        resp = self.perform_get_request_with_token('/v1/sayHello')
        self.assertEqual(200, resp.status, EXPECT_200)
        self.assertRegex(resp.body, self.credentials.username, 'Expected to find username in response')


class HttpUtil:
    class HttpResponse:
        def __init__(self, response, error=None):
            if error:
                self.body = error.reason
                self.status = error.code
                self.is_ok = False
            else:
                self.body = response.read().decode()
                self.status = response.status
                self.is_ok = True
            logging.debug(self)

        @classmethod
        def error(cls, error):
            return cls(response=None, error=error)

        def __str__(self):
            if len(self.body) > 150:
                body = self.body[:150] + '... (truncated)'
            else:
                body = self.body
            return 'HTTP status: {}, body: {}'.format(self.status, body)

    def get_request(self, url, access_token=None, additional_headers={}):
        logging.debug('Performing GET request to ' + url)
        req = urllib.request.Request(url, method='GET')
        self.__add_headers(req, access_token, additional_headers)
        return self.__execute(req)

    def post_request(self, url, data=None, access_token=None, additional_headers={}):
        logging.debug('Performing POST request to {} {}'
                      .format(url, 'with access token: ' + access_token if access_token else 'without access token'))
        req = urllib.request.Request(url, data=data, method='POST')
        self.__add_headers(req, access_token, additional_headers)
        return self.__execute(req)

    def post_request_x509(self, url, url_path, payload=None, access_token=None, certificate=None, key=None,
                          additional_headers=None):
        with open("cert.pem", "w") as cert_pem:
            cert_pem.write(certificate)
        with open("key.pem", "w") as key_pem:
            key_pem.write(key)
        host = url = url.replace("https://", "")

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if additional_headers is not None:
            headers.update(additional_headers)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Deprecated but PROTOCOL_TLS_CLIENT doesn't work
        context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

        connection = http.client.HTTPSConnection(host, port=443, context=context, timeout=500)
        connection.set_debuglevel(1)
        connection.request(method="POST", url=url_path, body=payload, headers=headers)

        logging.debug('Performing POST request over mTLS to {} {}'
                      .format(url, 'with access token: ' + access_token if access_token else 'without access token'))
        response = connection.getresponse()
        body_decoded = response.read().decode()
        logging.debug('Response from POST request over mTLS: status {} - data {}'.format(response.status, body_decoded))
        connection.close()
        if response.status == 200:
            return json.loads(body_decoded)
        else:
            logging.error('mTLS post request failed - {} {}'.format(response.status, response.body))
            return None

    def encode_request_body(self, clientid, grant_type, username=None, password=None):
        return urlencode({'client_id': clientid,
                                   'grant_type': grant_type,
                                   'response_type': 'token',
                                   'username': username,
                                   'password': password}).encode()

    def get_token(self, xsuaa_service_url, clientid, clientsecret, grant_type, username=None, password=None):
        post_req_body = urlencode({'client_id': clientid,
                                   'client_secret': clientsecret,
                                   'grant_type': grant_type,
                                   'response_type': 'token',
                                   'username': username,
                                   'password': password}).encode()
        url = xsuaa_service_url + '/oauth/token'
        resp = HttpUtil().post_request(url, data=post_req_body)
        if resp.is_ok:
            return json.loads(resp.body)
        else:
            logging.error('Could not retrieve access token')
            return None

    def get_id_token(self, ias_service_url, clientid, clientsecret="", certificate=None, key=None, grant_type='password',
                     username=None,
                     password=None):
        authorization_value = b64encode(bytes("{}:{}".format(clientid, clientsecret), 'utf-8')).decode("ascii")
        additional_headers = {'Authorization': 'Basic ' + authorization_value,
                              'Content-Type': 'application/x-www-form-urlencoded'}
        post_req_body = urlencode({'grant_type': grant_type,
                                   'response_type': 'id_token',
                                   'username': username,
                                   'password': password}).encode()

        if certificate is not None:
            return HttpUtil.post_request_x509(self, url=ias_service_url,
                                              url_path='/oauth2/token',
                                              payload=post_req_body,
                                              certificate=certificate,
                                              key=key,
                                              additional_headers=additional_headers)
        else:
            resp = HttpUtil().post_request(ias_service_url + '/oauth2/token',
                                           data=post_req_body,
                                           additional_headers=additional_headers)

        if resp.is_ok:
            logging.debug(resp.body)
            return json.loads(resp.body)
        else:
            logging.error('Could not retrieve id token. Error: {} - {}'.format(resp.status, resp.body))
            return None

    def __add_headers(self, req, access_token, additional_headers):
        if access_token:
            self.__add_header(req, 'Authorization', 'Bearer ' + access_token)
        for header_key in additional_headers:
            self.__add_header(req, header_key, additional_headers[header_key])

    def __add_header(self, req, header_name, header_value):
        logging.debug('adding HTTP header {} -> {}'.format(header_name, header_value))
        req.add_header(header_name, header_value)

    def __execute(self, req):
        try:
            res = urllib.request.urlopen(req)
            return HttpUtil.HttpResponse(response=res)
        except HTTPError as error:
            return HttpUtil.HttpResponse.error(error=error)


class IasAccess:
    def __init__(self, ias_name):
        self.ias_service_key_name = ias_name + '-key'
        self.ias_service_name = ias_name
        self.ias_service_url = None
        self.ias_client_id = None
        self.ias_client_secret = None
        self.ias_certificate = None
        self.ias_key = None
        self.ias_token = None
        self.__create_ias_service()
        self.__create_ias_service_key()
        self.__get_ias_service_key()

    @staticmethod
    def __extract_json_values(output, key):
        return output.get("credentials").get(key)

    def __create_ias_service(self):
        logging.info("Creating IAS service '{}'".format(self.ias_service_name))
        subprocess.call(['cf', 'create-service', 'identity', 'application', self.ias_service_name,
                         '-c', '{"xsuaa-cross-consumption": "true", "credential-type": "X509_GENERATED"}'], stdout=cf_logs)
        self.__wait_service_created()

    def __wait_service_created(self):
        progress = self.__check_service_progress()
        if "FAILED" in progress:
            raise Exception("Failed to create '{}' IAS service. {}".format(self.ias_service_name, progress))
        timer = 0
        while not "succeeded" in progress and timer < 280:
            logging.info("Waited {} seconds for IAS service '{}' to be created".format(timer, self.ias_service_name))
            time.sleep(7)
            timer += 7
            progress = self.__check_service_progress()
            if timer >= 280 or "FAILED" in progress:
                raise Exception("Failed to create '{}' IAS service. Timeout reached.".format(self.ias_service_name))
        logging.info("'{}' IAS service was created".format(self.ias_service_name))

    def __check_service_progress(self):
        output = subprocess.run(['cf', 'service', self.ias_service_name], capture_output=True)
        return output.stdout.decode()

    def __create_ias_service_key(self):
        logging.info("Creating service-key for {} IAS service with service-key name: {}"
                     .format(self.ias_service_name, self.ias_service_key_name))
        subprocess.run(['cf', 'create-service-key', self.ias_service_name,
                        self.ias_service_key_name, '-c', '{"credential-type": "X509_GENERATED"}'], stdout=cf_logs)

    def __get_ias_service_key(self):
        logging.info("Fetching service-key '{}' for '{}' IAS service"
                     .format(self.ias_service_name, self.ias_service_key_name))
        service_key_output = subprocess.run(
            ['cf', 'service-key', self.ias_service_name, self.ias_service_key_name], capture_output=True)
        lines = service_key_output.stdout.decode().split('\n')
        if lines is not None:
            json_output = json.loads(''.join(lines[1:]))
            self.ias_client_id = self.__extract_json_values(json_output, 'clientid')
            self.ias_client_secret = self.__extract_json_values(json_output, 'clientsecret')
            self.ias_service_url = self.__extract_json_values(json_output, 'url')
            self.ias_certificate = self.__extract_json_values(json_output, 'certificate')
            self.ias_key = self.__extract_json_values(json_output, 'key')

    def fetch_ias_token(self, user):
        logging.info("Fetching IAS token for '{}' IAS service".format(self.ias_service_name))
        self.ias_token = HttpUtil().get_id_token(
            ias_service_url=self.ias_service_url,
            clientid=self.ias_client_id,
            clientsecret=self.ias_client_secret,
            certificate=self.ias_certificate,
            key=self.ias_key,
            grant_type='password',
            username=user.credentials.username,
            password=user.credentials.password).get('id_token')
        if self.ias_token is None:
            logging.error("Cannot continue without id token")
            exit()
        logging.debug("IAS token: {}".format(self.ias_token))
        return self.ias_token

    def delete(self):
        logging.info("Deleting service key '{}' for '{}' IAS service"
                     .format(self.ias_service_key_name, self.ias_service_name))
        subprocess.run(['cf', 'delete-service-key', '-f',
                        self.ias_service_name, self.ias_service_key_name], stdout=cf_logs)
        logging.info("Deleting {} IAS service".format(self.ias_service_name))
        subprocess.run(['cf', 'delete-service', '-f', self.ias_service_name], stdout=cf_logs)


class ApiAccessService:

    def __init__(self, xsuaa_service_url, xsuaa_api_url, name='api-access-service'):
        self.name = name
        self.service_key_name = self.name + '-sk'
        self.xsuaa_api_url = xsuaa_api_url
        self.xsuaa_service_url = xsuaa_service_url
        self.http_util = HttpUtil()
        subprocess.run(['cf', 'create-service', 'xsuaa', 'apiaccess', name], stdout=cf_logs)
        subprocess.run(['cf', 'create-service-key', name,
                        self.service_key_name], stdout=cf_logs)
        service_key_output = subprocess.run(
            ['cf', 'service-key', name, self.service_key_name], capture_output=True)
        lines = service_key_output.stdout.decode().split('\n')
        self.data = json.loads(''.join(lines[1:]))
        logging.debug('Created ' + str(self))

    def delete(self):
        logging.info("Deleting '{}' service key".format(self.service_key_name))
        subprocess.run(['cf', 'delete-service-key', '-f',
                        self.name, self.service_key_name], stdout=cf_logs)
        logging.info("Deleting '{}' service".format(self.name))
        subprocess.run(['cf', 'delete-service', '-f', self.name], stdout=cf_logs)

    def get_user_by_username(self, username):
        query_parameters = urlencode(
            {'filter': 'userName eq "{}"'.format(username)})
        url = '{}/Users?{}'.format(self.xsuaa_api_url, query_parameters)
        res = self.http_util.get_request(
            url, access_token=self.__get_access_token())
        if not res.is_ok:
            self.__panic_user_not_found(username)
        users = json.loads(res.body).get('resources')
        if users is None or len(users) < 1:
            self.__panic_user_not_found(username)
        return users[0]

    def add_user_to_group(self, user_id, group_name, origin='sap.default'):
        post_req_body = json.dumps(
            {'value': user_id, 'origin': origin, 'type': 'USER'}).encode()
        url = '{}/Groups/{}/members'.format(self.xsuaa_api_url, group_name)
        return self.http_util.post_request(url, data=post_req_body,
                                           access_token=self.__get_access_token(),
                                           additional_headers={'Content-Type': 'application/json'})

    def __panic_user_not_found(self, username):
        logging.error('Could not find user {}'.format(username))
        exit()

    def __get_access_token(self):
        token = self.http_util.get_token(
            xsuaa_service_url=self.xsuaa_service_url,
            clientid=self.data.get('credentials').get('clientid'),
            clientsecret=self.data.get('credentials').get('clientsecret'),
            grant_type='client_credentials')
        return token.get('access_token')

    def __str__(self):
        formatted_data = json.dumps(self.data, indent=2)
        return 'Name: {}, Service-Key-Name: {}, Data: {}'.format(
            self.name, self.service_key_name, formatted_data)


class CFApps:
    def __init__(self):
        token = subprocess.run(['cf', 'oauth-token'], capture_output=True)
        target = subprocess.run(['cf', 'target'], capture_output=True)
        self.bearer_token = token.stdout.strip().decode()
        [self.cf_api_endpoint, self.user_id, space_name] = self.__parse_target_output(target.stdout.decode())
        space = subprocess.run(['cf', 'space', space_name, '--guid'], capture_output=True)
        self.space_guid = space.stdout.decode().strip()

    def app_by_name(self, app_name):
        url = '{}/apps?space_guids={}&names={}'.format(self.cf_api_endpoint, self.space_guid, app_name)
        paginated_apps = self.__get_with_token(url)
        app = self.__get_first_paginated_resource(paginated_apps)
        if app is None:
            logging.error('App {} not found'.format(app_name))
            exit()
        vcap_services = self.__vcap_services_by_guid(app.get('guid'))
        return DeployedApp(vcap_services)

    def __get_first_paginated_resource(self, paginated_resources):
        pagination = paginated_resources.get('pagination')
        if pagination and pagination.get('total_results') > 0:
            if pagination.get('total_results') > 1:
                logging.warning(
                    'More than one resource found, taking the first one!')
            return paginated_resources.get('resources')[0]

    def __get_with_token(self, url):
        attempts = 3
        res = HttpUtil().get_request(url, additional_headers={
            'Authorization': self.bearer_token})
        if res.status != 200 and attempts:
            self.bearer_token = subprocess.run(['cf', 'oauth-token'], capture_output=True).stdout.strip().decode()
        res = HttpUtil().get_request(url, additional_headers={
            'Authorization': self.bearer_token})
        return json.loads(res.body)

    def __vcap_services_by_guid(self, guid):
        env = self.__get_with_token(
            self.cf_api_endpoint + '/apps/{}/env'.format(guid))
        return env.get('system_env_json').get('VCAP_SERVICES')

    def __parse_target_output(self, target_output):
        api_endpoint_match = re.search(r'API endpoint:(.*)', target_output)  # required cf cli version < 7.3
        user_id_match = re.search(r'user:(.*)', target_output)
        space_match = re.search(r'space:(.*)', target_output)
        api_endpoint = api_endpoint_match.group(1)
        user_id = user_id_match.group(1)
        space_name = space_match.group(1)
        return [api_endpoint.strip() + '/v3', user_id.strip(), space_name.strip()]


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
            commented_line = re.search(r'^#', line)
            if commented_line is None:
                result += line + '\n'
        return result


class DeployedApp:
    """
        This class parses VCAP_SERVICES (as dictionary) and supplies its content, e.g.:
    >>> vcap_services = {'xsuaa': [{'label': 'xsuaa', 'provider': None, 'plan': 'application', 'name': 'xsuaa-java-security', 'tags': ['xsuaa'], 'instance_name': 'xsuaa-java-security', 'binding_name': None, 'credentials': {'tenantmode': 'dedicated', 'sburl': 'https://internal-xsuaa.authentication.sap.hana.ondemand.com', 'clientid': 'sb-java-security-usage!t1785', 'xsappname': 'java-security-usage!t1785', 'clientsecret': 'abc', 'url': 'https://test.authentication.sap.hana.ondemand.com', 'uaadomain': 'authentication.sap.hana.ondemand.com', 'identityzone': 'test01', 'identityzoneid': '54d48a27', 'tenantid': '54d48a27'}, 'syslog_drain_url': None, 'volume_mounts': []}],'identity': [{'label': 'identity', 'plan': 'application', 'name': 'ias-authn', 'credentials': {'clientid': 'clientid', 'clientsecret': 'efg', 'url': 'https://test.authentication.sap.hana.ondemand.com'}}]}
    >>> app = DeployedApp(vcap_services)
    >>> app.get_credentials_property('clientsecret')
    'abc'
    >>> app.clientsecret
    'abc'
    >>> app.get_ias_credentials_property('url')
    'https://test.authentication.sap.hana.ondemand.com'
    """

    """
        This class parses VCAP_SERVICES (as dictionary) and supplies its content, e.g.:
    >>> vcap_services = {'identity': [{'label': 'identity', 'application', 'name': 'xsuaa-java-security', 'tags': ['xsuaa'], 'instance_name': 'xsuaa-java-security', 'binding_name': None, 'credentials': {'tenantmode': 'dedicated', 'sburl': 'https://internal-xsuaa.authentication.sap.hana.ondemand.com', 'clientid': 'sb-java-security-usage!t1785', 'xsappname': 'java-security-usage!t1785', 'clientsecret': 'b1GhPeHArXQCimhsCiwOMzT8wOU=', 'url': 'https://saschatest01.authentication.sap.hana.ondemand.com', 'uaadomain': 'authentication.sap.hana.ondemand.com', 'identityzone': 'test01', 'identityzoneid': '54d48a27', 'tenantid': '54d48a27'}, 'syslog_drain_url': None, 'volume_mounts': []}]}
    >>> app = DeployedApp(vcap_services)
    >>> app.get_credentials_property('clientsecret')
    'b1GhPeHArXQCimhsCiwOMzT8wOU='
    >>> app.clientsecret
    'b1GhPeHArXQCimhsCiwOMzT8wOU='

    """

    def __init__(self, vcap_services):
        self.vcap_services = vcap_services
        if self.vcap_services.get('xsuaa') is not None:
            self.xsuaa_properties = self.vcap_services.get('xsuaa')[0]
        if self.vcap_services.get('identity') is not None:
            self.ias_properties = self.vcap_services.get('identity')[0]

    @property
    def xsuaa_api_url(self):
        return self.get_credentials_property('apiurl')

    @property
    def xsuaa_service_url(self):
        return self.get_credentials_property('url')

    @property
    def xsuaa_cert_url(self):
        return self.get_credentials_property('certurl')

    @property
    def clientid(self):
        return self.get_credentials_property('clientid')

    @property
    def clientsecret(self):
        return self.get_credentials_property('clientsecret')

    @property
    def certificate(self):
        return self.get_credentials_property('certificate')

    @property
    def key(self):
        return self.get_credentials_property('key')

    @property
    def credential_type(self):
        return self.get_credentials_property('credential-type')

    @property
    def ias_service_url(self):
        return self.get_ias_credentials_property('url')

    @property
    def ias_clientid(self):
        return self.get_ias_credentials_property('clientid')

    @property
    def ias_clientsecret(self):
        return self.get_ias_credentials_property('clientsecret')

    @property
    def ias_certificate(self):
        return self.get_ias_credentials_property('certificate')

    @property
    def ias_key(self):
        return self.get_ias_credentials_property('key')

    def get_credentials_property(self, property_name):
        return self.xsuaa_properties.get('credentials').get(property_name)

    def get_ias_credentials_property(self, property_name):
        return self.ias_properties.get('credentials').get(property_name)

    def __str__(self):
        return json.dumps(self.vcap_services, indent=2)


class CFApp:
    def __init__(self, name, xsuaa_service_name=None, app_router_name=None, identity_service_name=None, security_descriptor=None):
        if name is None:
            raise (Exception('Name must be provided'))
        self.name = name
        self.xsuaa_service_name = xsuaa_service_name
        self.app_router_name = app_router_name
        self.identity_service_name = identity_service_name
        self.ias_access = None
        if security_descriptor is None:
            self.security_descriptor = 'xs-security.json'
        else:
            self.security_descriptor = security_descriptor

    @property
    def working_dir(self):
        return './' + self.name

    def restart(self):
        subprocess.run(
            ['cf', 'restart', self.name],
            cwd=self.working_dir, stdout=cf_logs, check=True)

    def deploy(self):
        if self.xsuaa_service_name is not None:
            logging.info("Creating Xsuaa service '{}'".format(self.xsuaa_service_name))
            subprocess.run(
                ['cf', 'create-service', 'xsuaa', 'application', self.xsuaa_service_name, '-c', self.security_descriptor],
                cwd=self.working_dir, stdout=cf_logs, check=True)
        if self.identity_service_name is not None and self.ias_access is None:
            self.ias_access = IasAccess(self.identity_service_name)
        logging.info("Verifying '{}' application tests".format(self.name))
        subprocess.run(['mvn', 'clean', 'verify'], cwd=self.working_dir, stdout=java_logs)
        logging.info("Deploying '{}' to CF".format(self.name))
        subprocess.run(['cf', 'push', '--vars-file', '../vars.yml'], cwd=self.working_dir, stdout=cf_logs)
        logging.info("Test environment setup finished: " + self.__str__())

    def delete(self):
        logging.info("Deleting '{}'".format(self.name))
        if self.identity_service_name is not None:
            subprocess.run(['cf', 'us', self.name, self.identity_service_name], stdout=cf_logs)
        subprocess.run(['cf', 'delete', '-f', '-r', self.name], stdout=cf_logs)
        subprocess.run(['cf', 'delete-orphaned-routes', '-f'], stdout=cf_logs)
        if self.app_router_name is not None:
            logging.info("Deleting '{}' app router".format(self.app_router_name))
            subprocess.run(['cf', 'delete', '-f', '-r', self.app_router_name], stdout=cf_logs)
        logging.info("Deleting '{}' Xsuaa service".format(self.xsuaa_service_name))
        if self.xsuaa_service_name is not None:
            subprocess.run(['cf', 'delete-service', '-f', self.xsuaa_service_name], stdout=cf_logs)
        if self.identity_service_name is not None:
            self.ias_access.delete()

    def __str__(self):
        return 'Name: {}, Xsuaa-Service-Name: {}, App-Router-Name: {}, Identity-Service-Name: {}'.format(
            self.name, self.xsuaa_service_name, self.app_router_name, self.identity_service_name)


def is_logged_off():
    target = subprocess.run(['cf', 'target'], capture_output=True)
    return not target or target.stdout.decode().startswith('FAILED')


if __name__ == '__main__':
    if is_logged_off():
        print('To run this script you must be logged into CF via "cf login"')
        print('Also make sure to change settings in vars.yml')
    else:
        import doctest
        doctest.testmod()
        unittest.main()
