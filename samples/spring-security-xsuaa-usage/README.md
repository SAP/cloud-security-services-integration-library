## :warning: Deprecation Notice
This Sample is deprecated and will be removed with the next major release 4.x See [Migration guide](/spring-security/Migration_SpringXsuaaProjects.md) and use [spring-security-hybrid-usage](../spring-security-hybrid-usage) sample instead.

# Description
This sample is a Spring Boot application that utilizes the [`spring-xsuaa`](/spring-xsuaa/) client library uses the SAP application router as OAuth client and forwards as reverse proxy the requests to a Java Spring back-end application.
In a typical UI5 application, the application router serves HTML files and REST data would be provided by a back-end application. To focus on the security part, UI5 has been omitted.

Furthermore, it demonstrates how to leverage the token flows provided by the [Token Client](/token-client/) library to request exchange access tokens.

# Deployment To Cloud Foundry
To deploy the application, the following steps are required:
- Configure the Application Router
- Compile the Java application
- Create an XSUAA service instance
- Configure manifest.yml
- Deploy the application
- Assign Role Collection to your user
- Access the application

## Configure the Application Router

The [Application Router](./approuter/package.json) is used to provide a single entry point to a business application that consists of several different apps (microservices). It dispatches requests to backend microservices and acts as a reverse proxy. The rules that determine which request should be forwarded to which _destinations_ are called _routes_. The application router can be configured to authenticate the users and propagate the user information. Finally, the application router can serve static content.

## Compile the Java Application
Run maven to package the application
```shell
mvn clean package
```

## Create the XSUAA Service Instance
:exclamation: XSUAA supports X.509 authentication method.

- Use the [xs-security.json](./xs-security.json) to define the X.509 authentication method with Xsuaa managed certificate and create a service instance
- Use the [xs-security-deprecated.json](xs-security-deprecated.json) to define the authentication method with binding secret method and settings and create a service instance
```shell
cf create-service xsuaa application xsuaa-authentication -c xs-security.json
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that you might need to adopt.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Cockpit administration tasks: Assign Role to your User
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection(s) such as `Viewer` or `Administrator` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on sap.help.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).

## Access the application
After deployment, the AppRouter will trigger authentication automatically when you access one of the following URLs:

* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v1/sayHello` - GET request that provides XSUAA user token details, but only if token matches.
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v1/method` - GET request executes a method secured with Spring Global Method Security.
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v1/getAdminData` - GET request to read sensitive data via Global Method Security. You will get a `403` (UNAUTHORIZED), in case you do not have `Admin` scope.
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v2/sayHello` - GET request that logs generic Jwt info, but only if token matches. 
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v3/requestClientCredentialsToken` - GET request that requests the client credentials Jwt token and writes it into the log. 
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v3/requestUserToken` - GET request that exchanges a Jwt token for a potential different client.

Have a look into the logs with:
```
cf logs spring-security-xsuaa-usage --recent
cf logs approuter-spring-security-xsuaa-usage --recent
```

> Note: https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN> points to the url of the AppRouter. Get all app routes with `cf apps`.

## Clean-Up

Finally delete your application and your service instances using the following commands:
```
cf delete -f spring-security-xsuaa-usage
cf delete -f approuter-spring-security-xsuaa-usage
cf delete-service -f xsuaa-authentication
```
