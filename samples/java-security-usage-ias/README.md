# Description
This sample is a Java back-end application running on the Cloud Foundry. On incoming requests it checks whether the user is authorized using the 
[`OAuth2SecurityFilter`](src/main/java/com/sap/cloud/security/servlet/OAuth2SecurityFilter.java) which is defined in the [Java Security](../../java-security/) library.

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
cf create-service identity-beta default ias-java-security -c '{"redirect_uris": ["https://java-security-usage-ias-((ID)).((LANDSCAPE_APPS_DOMAIN))/uaa/login/callback/my-oidc"]}'
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Access the application
- Get an access token via `curl`. Make sure that you replace the placeholders `clientid`, `clientsecret` and `url` (without `https://` !!!) according to the service configuration that are stored as system environment variable `VCAP_SERVICES.identity-beta.credentials`. You can get them using `cf env java-security-usage-ias`. 

```
curl -X POST \
  https://<<clientid>>:<<clientsecret>>@<<url>>/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=<<your ias user>>&password=<<your ias password>>'
```

Copy the `id_token` into your clipboard.

- Access the app via `curl`. Don't forget to fill the placeholders.
```
curl -X GET \
  https://java-security-usage-ias-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/hello-java-security-ias \
  -H 'Authorization: Bearer <<your access_token>>'
```

You should see something like this:
```
You ('<your email>') are authenticated and can access the application.
```

## Clean-Up
Finally delete your application and your service instances using the following commands:
```
cf delete -f java-security-usage-ias
cf delete-service -f ias-java-security
```
