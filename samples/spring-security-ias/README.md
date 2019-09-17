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
-H 'x-forwarded-client-cert: MIID1TCCAr2gAwIBAgIMPh7OM/DYQU4AAAzsMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYTAkRFMRwwGgYDVQQKDBNTQVAgVHJ1c3QgQ29tbXVuaXR5MRswGQYDVQQDDBJTQVAgUGFzc3BvcnQgQ0EgRzIwHhcNMTkwOTE3MDYyMDI0WhcNMjAwOTE3MDYyMDI0WjCBqTELMAkGA1UEBhMCREUxHDAaBgNVBAoTE1NBUCBUcnVzdCBDb21tdW5pdHkxHTAbBgNVBAsTFHhzdWFhLXNlcnZpY2UtYnJva2VyMRwwGgYDVQQLExNDZXJ0aWZpY2F0ZSBTZXJ2aWNlMRAwDgYDVQQHEwdzYXAtdWFhMS0wKwYDVQQDEyRhNWNjMWM2Zi1iMmQ1LTQ1N2MtYTg4MS0zZGQ5ZjZmMDViZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtIap+VkkpORzysNGZ73arSSXl1qv0whFP2baPytdQxc0LHRfz5KTvy7sH2oxg/hNITjp6OuSMh0OjwRgAs1uklmf62uFEEqboAz5egaGkmdPtUWRCslfhhCHHskOn9z0gCR/dAl7sErz0KguxbT1urENahgl5uSSTcyxQgCqu3kcAbCZO/o4EKBBwmrvNK/8YH5I4A6WnMj0EK34vS7S9NFoZE4FPiuHrDlb1Zf1pa9joU2aD4Vgk0NGS8fpvQ7GDjHrzzwQGPOO7xf8jmnzWXpnTwhCenP75u3OYEXksjZjsX4gVO1AjC3ZdUjWa3qOjB30Is0uLM9F/vSVVZAh/AgMBAAGjXTBbMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgTwMB0GA1UdDgQWBBSg8dkw7KnGzLQb0p9NkCPGESjFTTAfBgNVHSMEGDAWgBSp7mnloV/30J2B2jAFTiIrAKefnjANBgkqhkiG9w0BAQsFAAOCAQEAhG0bt29kdv/4641tx/q4Ry3FOeOUoz7fpehoabpOIDcikvE+FWBNySFIVEB7OB6KTvjH2G8tX7vYXkYvUhHgLwzUxzRevETKlVLCt4aot/n09HI5TGLHBRRKQjWx8sPuJK9jkwGMSA/S1R6JvLyJ8WsiLJ44zwtC6FzaSChigvwVjyD5RkL4K1Z/pmO0xWm0EkCKVPpSBE0Ff/eU4yA1yEwBB/3E0NKF/3/TKj+qjfGPDy/njZ3Fuk+rWMFnt4OGxu3yUpTZ/2mvOWoqjGuc8j/jz9+iEMXIp2M4LQec0Onjg9ahHTMn822A5tt8NHOmlDH5dlLhFUMB8YY3uQSnAw=='
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

