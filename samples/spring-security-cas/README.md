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

This starts a docker container with OPA on that url `http://localhost:8181`.

* `<OPA_URL>/v1/data` returns the users and their policies  
* `<OPA_URL>/v1/policies` lists the divers policies
* `<OPA_URL>/v1/data/rbac/allow` POST request with Content-Type: application/json` and payload:
```
{
	"input": {
		"user": "Alice_readAll",
		"action": "read"
	}
}
```
... should return `true, whereas this payload for the same `user` but different `action`:
```
{
	"input": {
		"user": "Alice_readAll",
		"action": "debug"
	}
}
```
... should return false, as the user has no policy assigned with `action`="`debug`". 

Find the current API documentation of OPA (Open Policy Agent) [here](https://www.openpolicyagent.org/docs/latest/rest-api/).


### Configure the local environment
The Url of the Authorization Decision Controller (`OPA_URL`) is configured as part of system environment variable or in case of Spring via the [application.yml](src/main/resources/application.yml). 
In this sample, if `OPA_URL` is not configured `http://localhost:8181` is taken as default, which points to the [opa docker container](docker-compose.yaml).

### Start application
```
docker-compose up -d
source localEnvironmentSetup.sh
mvn spring-boot:run
```

### Test
When your application is successfully started (pls check the console logs) you can perform the following GET-requests with your browser:

- `http://localhost:8080/health` should return "ok" (Status Code `200`). If not please check the application logs using `cf logs spring-security-cas --recent`, whether the OPA (ADC) Service is unavailable.
- `http://localhost:8080/readByCountry/DE`  
This GET request executes a method secured with Spring Global Method Security. It will respond with error status code `403` (`unauthorized`) in case you do not have any Policies assigned, that grants access for action `read` on any resources in `Country` = `<your country Code, e.g. 'DE'>`.

Check the logs to find out the user id and the result of the authorization check. 
```
Is user <your user-id> authorized to perform action 'read' on resource 'null' and attributes '[Country=DE]' ? false
```
In case you have a lack of permissions you need to make sure that you (`<your user-id>`) have the same policy in `src/main/resources/amsBundle/data.json` assigned like the user with id `Alice_countryCode`. Afterwards you need to restart the docker-container 
```
docker restart spring-security-cas_opa_1
```
Now repeat the forbidden test requests.

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

## Access the application
After successful deployment, when accessing your application endpoints on Cloud Foundry, you get redirected to a login-screen to authenticate yourself. 

- `https://spring-security-cas-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/health` should return "ok" (Status Code `200`). If not please check the application logs using `cf logs spring-security-cas --recent`, whether the OPA (ADC) Service is unavailable.
- `https://spring-security-cas-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/readByCountry/{country}`  
This GET request executes a method secured with Spring Global Method Security. It will respond with error status code `403` (`unauthorized`) in case you do not have any Policies assigned, that grants access for action `read` on any resources in `Country` = `<your country Code, e.g. 'DE'>`.



## Clean-Up
Finally delete your application and your service instances using the following commands:
```
docker rm --force spring-security-cas_opa_1
cf delete spring-security-cas
cf delete-service spring-security-cas-ias
```