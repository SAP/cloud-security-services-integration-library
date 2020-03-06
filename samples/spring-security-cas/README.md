# Description
This sample is a Spring back-end application running on the Cloud Foundry. 
For all incoming requests it checks on the one hand whether the user is authenticated and on the other hand whether it is authorized using the **Cloud Authority Service (CAS)**.

CAS consists of several components, namely 
- the **Authorization Bundle Provider (ABP)**  
that stores and bundles application specific policy and data.
- the **Authorization Decision Controller (ADC)**  
that uses the [open source **Open Policy Agent (OPA)**](https://www.openpolicyagent.org/) to decide whether a given user has the policy to perform a dedicated action on a dedicated resource.


# Test Locally

## Access Authorization Decision Controller (ADC)
First, get familiar with the Authorization Decision Controller (ADC) service which uses the OPA policy engine.

1. Start the Open Policy Agent (OPA) locally as part of a docker container:  
    ```
    docker-compose up -d
    ```  
   > This starts a docker container with OPA on that url `http://localhost:8181`. It preconfigures OPA with all files that are provided in the `amsBundle` folder.

2. Perform some requests (using [`Postman` REST client](https://www.postman.com/))

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
    ... should return `true`, whereas a similar payload for the same `user` but different `action`:
    ```
    {
        "input": {
            "user": "Alice_readAll",
            "action": "debug"
        }
    }
    ```
    ... should return `false`, as the user has no policy assigned with `action`="`debug`". 

3. Find the current API documentation of OPA [here](https://www.openpolicyagent.org/docs/latest/rest-api/).

## Create the OAuth2 identity service instance
Use the xsuaa service broker and create a service instance
```shell
cf create-service xsuaa application spring-security-cas-authn -c '{ "xsappname": "spring-security-cas", "tenant-mode": "dedicated" }'
```
NOT YET SUPPORTED: Alternatively you can also create an IAS service instance (update the redirect uri to your "LANDSCAPE_APPS_DOMAIN")
```shell
cf create-service identity-broker-beta default spring-security-cas-authn -c '{"oauth2-configuration":{"redirect-uris": ["https://*.cfapps.sap.hana.ondemand.com/login/oauth2/code/ias"]}}''
```

## Configure the local environment
This demo application can be tested locally in a hybrid setup. That means that the application, as well as ADC runs locally but for the SSO setup it uses the OAuth2 Identity Service that was created on Cloud Foundry in the previous step. Perform these steps to adapt your configuration.

1. Get the `clientid`, the `clientsecret` and the `url` from your Identity Service as follows
    ```shell
    cf create-service-key spring-security-cas-authn spring-security-cas-sk
    cf service-key spring-security-cas-authn spring-security-cas-sk
    ```

1. Open the `/src/main/resources/application.yml` file and configure the `issuer_uri` with the `url`. In case of xsuaa service instance, you have to enhance the url by `/oauth/token`. Save the file changes.
1. Open the `localEnvironmentSetup.sh` file and update`the values for clientid` and `clientsecret` accordingly. Save the file changes.

> Note: The url of the Authorization Decision Controller (`OPA_URL`) is configured as system environment variable or as part of [application.yml](src/main/resources/application.yml) in case of Spring applications. 
In this sample, if `OPA_URL` is not configured `http://localhost:8181` is taken as default, which points to the [opa docker container](docker-compose.yaml).

## Start application locally
```
docker-compose up -d
source localEnvironmentSetup.sh
mvn spring-boot:run
```

## Test locally
When your application is successfully started (pls check the console logs) you can perform the following GET-requests with your browser:

- `http://localhost:8080/health` should return "ok" (Status Code `200`). If not please check the application logs using `cf logs spring-security-cas --recent`, whether the OPA (ADC) Service is unavailable.
- `http://localhost:8080/readByCountry/DE`  
This GET request executes a method secured with Spring Global Method Security. It will respond with error status code `403` (`unauthorized`) in case you do not have any policy assigned, that grants access for action `read` on any resources in `Country` = `<your country Code, e.g. 'DE'>`.

Check the application logs on your console to find out the user id and the result of the authorization check. 
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

On Cloud Foundry the ADC Service gets deployed together with your application (as a sidecar). In the manifest you may need to adapt the route to your Authorization Bundle Provider (ABP). This serves on the one side the rules and policies as part of the `.rego` files and on the other side the data which contains the assignments of users to policies. During start-up the ADC service fetches the bundle from the ABP service.

![](images/adc_abpInteraction.png)

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Upload your user-specific bundle
You have to make sure that the bundle serves your bundle, with your user-policy assignments. So, we need to upload all files from the `amsBundle` folder. We have to perform a `POST` request to the ABP service `https://abp.cfapps.sap.hana.ondemand.com/sap/cas/v1/bundles/((ID)).tar.gz` and specify your files in context of `data` form parameter as depicted in the screen shot below. 

> Don't forget to replace the `((ID))` placeholder accordingly (as specified in `../vars.yml`)!!

![](images/postmanUploadBundle.png)


## Compile and deploy the application
Deploy te application using `cf push`. It will expect 800MB of free memory quota.

```shell
mvn clean package
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
cf delete-service-key spring-security-cas-authn spring-security-cas-sk
cf delete spring-security-cas
cf delete-service spring-security-cas-authn
```