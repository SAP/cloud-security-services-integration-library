# Description
This sample is a Java Back-End application that demonstrates usage of [SAP Java Buildpack](https://help.sap.com/docs/btp/sap-business-technology-platform/developing-java-in-cloud-foundry-environment).
SAP Java Buildpack bundles the [Java Security](/java-security/) client library to authenticate JWT tokens issued by the `Xsuaa` service.
It inspects incoming requests to determine if the user has the appropriate authorization by using the [`XsuaaTokenAuthenticator`](/java-security/src/main/java/com/sap/cloud/security/servlet/XsuaaTokenAuthenticator.java).

:warning: Please note that this sample is based on the `java-security` library, which requires the Tomcat 10 runtime.
Therefore, it needs to be deployed using the [SAP Java Buildpack 2](https://help.sap.com/docs/btp/sap-business-technology-platform/sap-jakarta-buildpack) (sap_java_buildpack_jakarta).

In a typical UI5 application, the application router server HTML files and REST data would be provided by a back-end application. To focus on the security part, UI5 has been omitted.

> :bulb: This application manages your SAP Java buildpack dependencies using [Bill of Materials](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/6c6936e8e4ea40c9a9a69f6783b1e978.html). Check [SJB BoM on Maven Repository](https://mvnrepository.com/artifact/com.sap.cloud.sjb.cf/sap-java-buildpack-bom) to see which versions are provided.

The [web.xml](src/main/webapp/WEB-INF/web.xml) of the application must use auth-method with value `XSUAA`. This enables authentication of requests using incoming OAuth authentication tokens.

```xml
<web-app>
<display-name>sample</display-name>
  <login-config> 
    <auth-method>XSUAA</auth-method>
  </login-config> 
</web-app> 
```

In your Web Servlet, use then the `@ServletSecurity` annotations as implemented in [HelloTokenServlet](/samples/sap-java-buildpack-api-usage/src/main/java/sample/sapbuildpack/xsuaa/HelloTokenServlet.java).

# Deployment on Cloud Foundry
To deploy the application, the following steps are required:
- Configure the Application Router
- Compile the Java application
- Create a xsuaa service instance
- Configure the manifest
- Deploy the application
git
- Access the application

## Configure the Application Router
The [Application Router](./approuter/package.json) is used to provide a single entry point to a business application that consists of several different apps (microservices). It dispatches requests to backend microservices and acts as a reverse proxy. The rules that determine which request should be forwarded to which _destinations_ are called _routes_. The application router can be configured to authenticate the users and propagate the user information. Finally, the application router can serve static content.

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```

## Create the xsuaa service instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a service instance
```shell
cf create-service xsuaa application xsuaa-buildpack -c xs-security.json
```

## Configure the manifest

The [vars](../vars.yml) contains hosts and paths that need to be adopted.

This sample uses the `AccessToken` interface to extract user data from the principal. For this to work the environment
variable `ENABLE_SECURITY_JAVA_API_V2` is set to `true`. This can be done in the `manifest.yml` file inside the
configuration block of the `sap-java-buildpack-api-usage` application. With this flag set to `true` the principal from
`HttpServlet.getUserPrincipal()` will contain an `AccessToken` instead of a `XSUserInfo`.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Cockpit administration tasks: Assign Role to your User
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection(s) such as `Buildpack_API_Viewer` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on sap.help.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).

## Access the application
After deployment, the application router will trigger authentication. If you have assigned the role-collection provided in the [xs-security.json](./xs-security.json) to your user, you will see an output like when calling `https://approuter-sap-java-buildpack-api-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>`:

```
Client ID: sap-java-buildpack-api-usage!t5721
Email: user@mail
Family Name: Jones
First Name: Bob
OAuth Grant Type: authorization_code
OAuth Token: eyJhbGciOiJSUzI1NiIsInR5...
```
If not you should get a `403` status code (Forbidden).

> Note: you can find the route of your approuter application using `cf app approuter-sap-java-buildpack-api-usage`.

## Clean-Up

Finally, delete your application and your service instances using the following commands:
```
cf delete -f sap-java-buildpack-api-usage
cf delete -f approuter-sap-java-buildpack-api-usage
cf delete-service -f xsuaa-buildpack
```
