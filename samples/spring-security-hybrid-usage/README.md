# Description
This spring boot application sample uses ```spring-security``` client library to validate jwt tokens issued by ```xsuaa``` service or by ```identity ``` service. On the one hand ```xsuaa``` service issues an access token and on the other hand ```identity``` service issues an oidc token. The tokens vary with regard to the information provided via token claims. In both cases the validated token is available of type [```Token```](https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/java-api/src/main/java/com/sap/cloud/security/token/Token.java) via the ```SecurityContextHolder```.

# Coding
This sample is using the [`spring-security`](/spring-security/) library which bases on [Spring's Security](https://github.com/spring-projects/spring-security) project. It integrates with [Spring Security OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver). The security configuration needs to configure jwt for authentication.


# Deployment To Cloud Foundry
To deploy the application, the following steps are required:
- Compile the Java application
- Create a XSUAA service instance
- Create an Identity service instance
- Configure manifest.yml
- Deploy the application
- Admin: Assign Role Collection to your XSUAA user
- Admin: Assign Group to your IAS user
- Access the application

## Compile the Java Application
Run maven to package the application
```shell
mvn clean package
```

## Create the XSUAA Service Instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a xsuaa service instance
```shell
cf create-service xsuaa application xsuaa-authn -c xs-security.json
```

## Create the IAS Service Instance
Use the ias service broker and create an identity service instance
```shell
cf create-service identity application ias-authn
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that you might need to adopt.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```
> Note: In case of this error message `An operation for service instance ias-authn is in progress.` wait a moment, as identity service instance gets created asynchronously.

## Cockpit administration task: Assign Xsuaa Role Collection to your User
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection(s) such as `Viewer` or `Administrator` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on sap.help.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).

## IAS User administration task: Assign Group to your User
You need administrator permissions to create a Groups "Read" in IAS and assign it to your user.

## Access the application
- create an IAS oidc token via ``password`` grant token flow. For that call the ``oauth2/token`` endpoint of your identity service. You can get the ``url`` and the ``clientid`` and ``clientsecret`` for the Basic Authorization header from ``VCAP_SERVICES``.`identity`.
- create an XSUAA access token via ``password`` grant token flow. For that call the ``oauth/token`` endpoint of your xsuaa service. You can get the ``url`` and the ``clientid`` and ``clientsecret`` for the Basic Authorization header from ``VCAP_SERVICES``.`xsuaa`.

Call the following endpoints with ```Authorization``` header = "Bearer <your IAS/XSUAA token>"
* `https://spring-security-hybrid-usage-<ID>.<LANDSCAPE_APPS_DOMAIN>/sayHello` - GET request that provides token details, but only if token provides expected read permission (scope/groups).
* `https://spring-security-hybrid-usage-<ID>.<LANDSCAPE_APPS_DOMAIN>/method` - GET request executes a method secured with Spring Global Method Security, user requires read permission (scope/groups).

Have a look into the logs with:
```
cf logs spring-security-hybrid-usage --recent
```


## Clean-Up

Finally delete your application and your service instances using the following commands:
```
cf delete -f spring-security-hybrid-usage
cf delete-service -f xsuaa-authn
cf delete-service -f ias-authn
```
