# Description
This sample is a Spring back-end application running on the Cloud Foundry. 
For all incoming requests it checks on the one hand whether the user is authenticated and on the other hand whether it is authorized using Cloud Authority service. For authentication of the caller, it establishes an oAuth2 (OIDC) flow with the IAS service.

# Test Locally
First, get familiar with the Authorization Decision Controller (ADC) which uses the Open Policy Agent (OPA) framework.

## Access Authorization Decision Controller (ADC) via Open Policy Agent endpoints

Start the Open Policy Agent as part of a docker container:
```
docker-compose up -d
```

* `<OPA_URL>/v1/policies`
* `<OPA_URL>/v1/data`
* `<OPA_URL>/v1/data/rbac/allow` POST request with Content-Type: application/json and payload:
```
{
	"input": {
		"user": "Alice_readAll",
		"action": "read"
	}
}
```
should return true, whereas this payload for the same `user` but different `action`:
```
{
	"input": {
		"user": "Alice_readAll",
		"action": "debug"
	}
}
```
should return false, as the user has no policy assigned with rule (action) `debug`. 

Apply also a check on scope or attribute values using a token that simulates an Admin user:
```

```

Find the current API documentation of OPA (Open Policy Agent) [here](https://www.openpolicyagent.org/docs/latest/rest-api/).


### Configure the local environment
The Url of the Authorization Decision Controller (`OPA_URL`) is configured as part of system environment variable or in case of Spring via the [application.yml](src/main/resources/application.yml). 
In this sample, if it is not configured `http://localhost:8181` is taken as default, which points to the [opa docker container](docker-compose.yaml).

### Start application
```
docker-compose up -d
source localEnvironmentSetup.sh
mvn spring-boot:run -Dspring-boot.run.profiles=cloud
```

### Test
When your application is successfully started (pls check the console logs) use a Rest client such as `Postman Chrome Extension`. Then you can perform a GET request to `http://localhost:8080/v1/method` and set an `Authorization` header with the value 
```
Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzMxOTUvdG9rZW5fa2V5cyIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkifQ.eyJleHRfYXR0ciI6eyJ6ZG4iOiIifSwiemlkIjoidWFhIiwiemRuIjoiIiwiZ3JhbnRfdHlwZSI6InVybjppZXRmOnBhcmFtczpvYXV0aDpncmFudC10eXBlOnNhbWwyLWJlYXJlciIsInVzZXJfbmFtZSI6IkJvYmJ5Iiwib3JpZ2luIjoidXNlcklkcCIsImV4cCI6Njk3NDAzMTYwMCwiaWF0IjoxNTgwOTgwNTk0LCJlbWFpbCI6IkJvYmJ5QHRlc3Qub3JnIiwiY2lkIjoic2Itc3ByaW5nLXNlY3VyaXR5LWFkYy11c2FnZSF0MTQ4NjYifQ.xYjcNcYOIr2He5F70UqO1jU9gqlBmPsuPFgN6ym2gv9t6lDgqGnYJW9LA5qn-TJF0s4P-CebZwsqSoZyNcU_x_cwIXbaXGn_SqA_TWiQ4rzHqb-tHy78ReKHbls0P7j2aeaRBK_-l5Yr4qTbRtXMaxkYdN4F3yiYDJh1fpqdiLqaxrVP0W3c13CkR6HjzHDmWK_d4VkEakU4IdU2UUcYpbyijtYca-tLlFw2aZKCdYn2PZkRO8l00vX7ymd-wqOv6mmnttiitBBmTo62wd_x0USOG1sHEOzSlE40J0T4TB7JK08jvsX6wzLtAnMiBAaHPf_o48YGmHWNNbnGmsW2KQ
```
Alternatively you can also debug the [TestControllerTest](src/test/java/sample.spring.adc/TestControllerTest.java) JUnit Test. 


# Deployment on Cloud Foundry
To deploy the application, the following steps are required:
- Compile the Java application
- Create a ias service instance
- Configure the manifest
- Deploy the application    
- Access the application

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```


## Create the ias service instance
Use the ias service broker and create a service instance (don't forget to replace the placeholders)
```shell
cf create-service identity-beta default spring-security-cas-ias -c ‘{“redirect_uris”: [“https://*.cfapps.sap.hana.ondemand.com/login/oauth2/code/ias”]}’
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Access the application via cURL
After successful deployment, when accessing your application endpoints on Cloud Foundry, you get redirected to a login-screen to authenticate yourself. But your application will respond with error status code `403` (`unauthorized`) in case you do not have any Policies assigned.

- Get an id token via `cURL`. Make sure that you replace the placeholders `clientid`, `clientsecret` and `url` (without `https://` !!!) according to the service configuration that are stored as system environment variable `VCAP_SERVICES.identity-beta.credentials`. You can get them using `cf env spring-security-cas-ias`. 

```
curl -X POST \
  https://<<clientid>>:<<clientsecret>>@<<url>>/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=<<your ias user>>&password=<<your ias password>>'
```

Copy the `id_token` into your clipboard.

- Access the application via `curl`. Don't forget to fill the placeholders.
```
curl -X GET \
  https://spring-security-cas-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/v1/method \
  -H 'Authorization: Bearer <<your id_token>>'
```

This GET request executes a method secured with Spring Global Method Security. 
This method requires a policy e.g. `john.doe@sap.com_read`. You should see something like this:
```
You ('<your email>') are authenticated and can access the application.
```


## Clean-Up
Finally delete your application and your service instances using the following commands:
```
cf delete cf delete spring-security-cas-usage
cf delete-service spring-security-cas-ias
```