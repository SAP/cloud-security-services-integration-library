# Description
This sample uses the SAP application router as OAuth client and forwards as reverse proxy the requests to a Java Spring back-end application running on Cloud Foundry.
In a typical UI5 application, the application router serves HTML files and REST data would be provided by a back-end application. To focus on the security part, UI5 has been omitted.

# Coding
This sample is using the [`spring-xsuaa`](/spring-xsuaa/) library which bases on [spring-security](https://github.com/spring-projects/spring-security) project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. The security configuration needs to configure JWT for authentication.

Furthermore it demonstrates how to leverage the token flows provided by the [Token Client](/token-client/) library to request / exchange access tokens.

# Deployment To Cloud Foundry
To deploy the application, the following steps are required:
- Configure the Application Router
- Compile the Java application
- Create an XSUAA service instance
- Configure manifest.yml
- Deploy the application
- Assign Role Collection to your user
- Access the application

## Compile the Java Application
Run maven to package the application
```shell
mvn clean package
```

## Create the XSUAA Service Instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a service instance
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
TODO

## Clean-Up

Finally delete your application and your service instances using the following commands:
```
cf delete -f spring-security-hybrid-usage
cf delete-service -f xsuaa-authentication
```
