# Description
This sample is a Java Back-End application that utilizes the [Java Security](../../java-security/) client library to validate JWT tokens issued by the `Identity` service.
It inspects incoming requests to determine if the user has the appropriate access to resource
by using the [`IasTokenAuthenticator`](/java-security/src/main/java/com/sap/cloud/security/servlet/IasTokenAuthenticator.java).\

**Disclaimer: as of now the Identity tokens can only be validated in case the token from the consuming application is issued for the same Identity tenant.**

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
cf create-service identity application ias-java-security
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Access the application
1. Follow [HowToFetchToken](../../docs/HowToFetchToken.md#ias-tokens) guide to fetch IAS id token.
 
   You can get the information to fill the placeholders from your system environment `cf env java-security-usage-ias`   

   Copy the `id_token` to your clipboard.

2. Access the app via `curl`. Don't forget to fill the placeholders.
   ```
   curl -X GET \
     https://java-security-usage-ias-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/hello-java-security-ias \
     -H 'Authorization: Bearer <<your id_token>>'
   ```

3. You should see something like this:
   ```
   You ('<your email>') are authenticated and can access the application.
   ```
   :bulb: If you call the same endpoint without `Authorization` header you should get a `401`.

## Clean-Up
Finally, delete your application and your service instances using the following commands:
```
cf us java-security-usage-ias ias-java-security
cf delete -f java-security-usage-ias
cf delete-service -f ias-java-security
```
