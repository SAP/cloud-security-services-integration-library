# Description
In some situations, the client does not support OAuth protocols so you need to fall back to  authentication. This sample uses a implementation of the [BearerTokenResolver](https://docs.spring.io/spring-security/site/docs/5.1.1.RELEASE/api/org/springframework/security/oauth2/server/resource/web/BearerTokenResolver.html). Depending on the configuration, this resolver will
- Support OAuth JWT tokens and
  - either exchange incoming credentials using the OAuth password grant flow
  - or exchange incoming credentials using the OAuth client credential flow

# Coding
This sample is using the spring-security project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. It enables caching using [`Caffeine`](https://github.com/ben-manes/caffeine) to avoid requesting new tokens from XSUAA for every incoming request.

# Deployment on Cloud Foundry
To deploy the application, the following steps are required:
- Compile the Java application
- Create a XSUAA service instance
- Configure the manifest.yml
- Deploy the application
- Access the application

## TODO remove: Test the Java application locally
```shell
source localEnvironmentSetup.sh
mvn spring-boot:run
```


## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```

## Create the XSUAA service instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a service instance
```shell
cf create-service xsuaa broker xsuaa-ias -c xs-security.json
```

> Note that your subaccount needs to be activated for certificates! 

## Configuration the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```


## Access the application
After deployment, the spring service can be called with X.509 certificate:
```shell
curl -X GET https://spring-security-ias-<ID>.<LANDSCAPE_APPS_DOMAIN>/hello-token 
-H 'Authorization: Bearer xxyz'
-H 'x-forwarded-client-cert: MIID1TCCAr2gAwIBAgIMTaP2W8RviIoAADmMMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYTAkRFMRwwGgYDVQQKDBNTQVAgVHJ1c3QgQ29tbXVuaXR5MRswGQYDVQQDDBJTQVAgUGFzc3BvcnQgQ0EgRzIwHhcNMTkxMDA4MTExNzI4WhcNMjAxMDA4MTExNzI4WjCBqTELMAkGA1UEBhMCREUxHDAaBgNVBAoTE1NBUCBUcnVzdCBDb21tdW5pdHkxHTAbBgNVBAsTFHhzdWFhLXNlcnZpY2UtYnJva2VyMRwwGgYDVQQLExNDZXJ0aWZpY2F0ZSBTZXJ2aWNlMRAwDgYDVQQHEwdzYXAtdWFhMS0wKwYDVQQDEyRhMjA2NDljNy0xMzQ1LTRiYjMtODU1My1jMzlhYzE4MDUxODgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjuhWZfF+iYK0m5Ks2/yn7Y/GSoJrrJjXJy0NjmBWW4z/PyHGPVMvs6Qtcbp3DnhqSEeqsx2xphAFYHyO/KFMFbknM7RKpbwopXvUFZLC3TXoRuEDKfUfHt7mKyXYpBzdMLT77cV28EampENaeom0v09+eWPTtP7czfTYSDlyXwKh7agh9fw7cYz0vgmEDamJJeeBqWaiaZ8mrLmwd8KDXj5hOwKod8t/yh4B3T6FlbNIOLnYt2hR9shZRqu1ZigpEq9LbSvbjLnZJMbpefOu5wAaU2VlX2vPGU+dfPenEbl2+f2o4rxvl59rIyL8rdlHCG1nkE4w7t4st12ObOASJAgMBAAGjXTBbMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgTwMB0GA1UdDgQWBBSQqBqdUAQt5yJKT5dkLO+0sNZy9TAfBgNVHSMEGDAWgBSp7mnloV/30J2B2jAFTiIrAKefnjANBgkqhkiG9w0BAQsFAAOCAQEAZnpqmn1gFMvrtw5wYXRJlxmhCbfC6FEK7htozcqa/xzku48h9w1zk+dQCTOc1FvEvCFRte2sMrMAkFrWtXp68t0H+h1v4tMismvDWR9y/wLvuFmNh1iqdmPAJLQqfgKrteCEhvmOfTXiCKtaQ4m94O7V5UJ8YXfnvZpr3+hF4g6uS4pXmfHs5PXHfs36uLDx6QfRzttRrUMqJD/vq/KcilbAI+T3KVmoXaTYq8Y8kkTgvrpYGqKvN2N7IfEEt2J1bgYqOhubJT4/yUr8zqXr8Sdl1343tjfq8G2kcSBFwBTAERK4zrRkGIitOdDEG3EkkoGDLGLzh75vkv+GSqL8ZA=='
```

You will get a response like:
```
{
  "client id": "sb-spring-security-xsuaa-usage!t291",
  "family name": "Jones",
  "given name": "Bob",
  "subaccount id": "2f047cc0-4364-4d8b-ae70-b8bd39d15bf0",
  "logon name": "bob.jones@example.com",
  "email": "bob.jones@example.com",
  "grant type": "password",
  "authorities": "[openid, spring-security-ias!t19435.Display]",
  "scopes": "[openid, spring-security-ias!t19435.Display]"
}
```

## Clean-Up

Finally delete your application and your service instances using the following commands:
```
cf delete -f spring-security-ias
cf delete-service -f xsuaa-ias
```

