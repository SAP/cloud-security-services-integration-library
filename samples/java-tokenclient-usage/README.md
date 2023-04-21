# Description
This sample showcases a Java back-end application leveraging the [Token Client](/token-client/) library 
to illustrate the token flow process of obtaining an Access Token issued by Xsuaa. 
Upon receiving incoming requests, the application retrieves credentials from the `VCAP_SERVICES` environment variable 
and requests a new access token through [ClientCredentialsTokenFlow](/token-client/src/main/java/com/sap/cloud/security/xsuaa/tokenflows/ClientCredentialsTokenFlow.java).

# Deployment on Cloud Foundry
To deploy the application, the following steps are required:
- Compile the Java application
- Create a xsuaa service instance
- Configure the manifest
- Deploy the application
- Access the application

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```

## Create the xsuaa service instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a service instance
```shell
cf create-service xsuaa application xsuaa-token-client -c xs-security.json
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Access the application
To access the application go to `https://java-tokenclient-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/hello-token-client`
You should see something like this:
```
Access-Token: eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vYzUyOTU0MDB0cmlhbC5hdXRoZW50aWN...
Access-Token-Payload: {"jti":"a2ea5313e37345709985836b1400305f","ext_attr":{"enhancer":"XSUAA","zdn":"c5295400trial"},...
Expired-At: Wed Oct 16 13:37:00 UTC 2019
```

## Clean-Up
Finally, delete your application and your service instances using the following commands:
```
cf delete -f java-tokenclient-usage
cf delete-service -f xsuaa-token-client
```
