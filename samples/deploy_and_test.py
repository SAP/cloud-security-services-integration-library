#!/usr/bin/env python3
import subprocess
import urllib.request
import urllib.parse
import json

cf_api = 'https://api.cf.sap.hana.ondemand.com/v3'

def get_bearer_token():
    token = subprocess.run(['cf', 'oauth-token'], capture_output=True)
    return token.stdout.strip().decode()

class CFUtil:
    def __init__(self, bearer_token):
        self.bearer_token = bearer_token
        self.apps = self.__retrieve_apps()

    def __get_with_token(self, url):
        req = urllib.request.Request(url)
        req.add_header('Authorization', self.bearer_token)
        res = urllib.request.urlopen(req)
        return json.loads(res.read().decode())

    def __retrieve_apps(self):
        return self.__get_with_token(cf_api + '/apps').get('resources')

    def app_by_name(self, app_name):
        for app in self.apps:
            if (app.get("name") == app_name):
                return app
    
    def env_by_app_name(self, app_name):
        app = self.app_by_name(app_name)
        guid = app.get('guid')
        return self.__get_with_token(cf_api + '/apps/{}/env'.format(guid))
    
class CFApp:
    def __init__(self, name, xsuaa_service_name, app_router_name=None):
        self.name = name
        self.xsuaaServiceName = xsuaa_service_name
        self.appRouterName = app_router_name

    def working_dir(self):
        return './' + self.name

    def deploy(self):
        subprocess.run(['cf', 'create-service', 'xsuaa', 'application',
                        self.xsuaaServiceName, '-c', 'xs-security.json'], cwd=self.working_dir())
        subprocess.run(['mvn', 'clean', 'verify'], cwd=self.working_dir())
        subprocess.run(['cf', 'push', '--vars-file',
                        '../vars.yml'], cwd=self.working_dir())

    def delete(self):
        subprocess.run(['cf',  'delete', '-f', self.name])
        subprocess.run(['cf',  'delete-service', '-f', self.xsuaaServiceName])
        if (self.appRouterName != None):
            subprocess.run(['cf',  'delete',  '-f', self.appRouterName])

apps = [
    CFApp(name="java-security-usage", xsuaa_service_name="xsuaa-java-security"),
    CFApp(name="java-tokenclient-usage", xsuaa_service_name="xsuaa-token-client"),
    CFApp(name="sap-java-buildpack-api-usage",
          xsuaa_service_name="xsuaa-buildpack"),
    CFApp(name="spring-security-basic-auth", xsuaa_service_name="xsuaa-basic"),
    CFApp(name="spring-security-xsuaa-usage", xsuaa_service_name="xsuaa-authentication",
          app_router_name="approuter-spring-security-xsuaa-usage"),
    CFApp(name="spring-webflux-security-xsuaa-usage", xsuaa_service_name="xsuaa-webflux",
          app_router_name="approuter-spring-webflux-security-xsuaa-usage")
]

# for app in apps:
# app.delete()

apps[0].delete()
apps[0].deploy()
cfUtil = CFUtil(get_bearer_token())
env = cfUtil.env_by_app_name(apps[0].name)
print(env)