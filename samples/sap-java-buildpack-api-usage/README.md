# SAP BTP Java Security Client Library Buildpack sample application
This Java backend application demonstrates the usage of the [SAP Java Buildpack](https://help.sap.com/docs/btp/sap-business-technology-platform/developing-java-in-cloud-foundry-environment).
The SAP Java Buildpack bundles the [java-security](/java-security/) module, which is used to validate JWT tokens issued by the `XSUAA` service.
Authentication and authorization of incoming requests are handled using the [`XsuaaTokenAuthenticator`](/java-security/src/main/java/com/sap/cloud/security/servlet/XsuaaTokenAuthenticator.java).

:warning: Please note that this sample is based on the `java-security` module, which requires the Tomcat 10 runtime.
Therefore, it needs to be deployed using the [SAP Java Buildpack 2](https://help.sap.com/docs/btp/sap-business-technology-platform/sap-jakarta-buildpack) (sap_java_buildpack_jakarta).

In a typical UI5 application, the application router serves HTML files and REST data would be provided by a back-end application.
To focus on the security part, UI5 has been omitted.

:bulb: This application manages your SAP Java buildpack dependencies using [Bill of Materials](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/6c6936e8e4ea40c9a9a69f6783b1e978.html). Check [SJB BoM on Maven Repository](https://mvnrepository.com/artifact/com.sap.cloud.sjb.cf/sap-java-buildpack-bom) to see which versions are provided.

The [web.xml](src/main/webapp/WEB-INF/web.xml) of the application must use auth-method with value `XSUAA`.
This enables authentication of requests using incoming OAuth tokens.

```xml
<web-app>
  <login-config> 
    <auth-method>XSUAA</auth-method>
  </login-config> 
</web-app> 
```

In your Web Servlet, then use the `@ServletSecurity` annotation as showcased in [HelloTokenServlet](src/main/java/sample/sapbuildpack/xsuaa/HelloTokenServlet.java).

## Configure the Application Router
The [Application Router](approuter/package.json) is used to provide a single entry point to a business application that consists of several different apps (microservices).
It dispatches requests to backend microservices and acts as a reverse proxy.
The rules that determine which request should be forwarded to which _destinations_ are called _routes_.
The application router can be configured to authenticate the users and propagate the user information.
Finally, the application router can serve static content.

## Build and Deploy
### 1. Run maven to compile and package the sample application:
```shell
mvn clean package
```

### 2. The following steps deploy the application using Cloud Foundry.
#### Create the XSUAA service instance
Use the cf CLI to create an XSUAA service instance based on the authentication settings in [xs-security.json](xs-security.json).
```shell
cf create-service xsuaa application xsuaa-buildpack -c xs-security.json
```

#### Configure the manifest
The [vars](../vars.yml) contain hosts and paths that need to be adapted.

This sample uses the `AccessToken` interface to extract user data from the principal. For this to work the environment
variable `ENABLE_SECURITY_JAVA_API_V2` is set to `true`. This can be done in the [`manifest.yml`](manifest.yml) file inside the
configuration block of the `sap-java-buildpack-api-usage` application. With this flag set to `true` the principal from
`HttpServlet.getUserPrincipal()` will contain an `AccessToken` instead of a `XSUserInfo`.

#### Deploy the application
Deploy the application using the cf CLI.

```shell
cf push --vars-file ../vars.yml
```
:warning: This will expect 1 GB of free memory quota.

### 3. Assign Role Collection to user
:bulb: You can postpone this step if you first want to test the application without the required authorization.

To get full access to the sample application, you need a user having the role collection `Sample Viewer (java-security-usage)` assigned.
This can be done in the SAP BTP Cockpit or using the btp CLI.

<details>
<summary>Assign role collection via cockpit</summary>
In the cockpit navigate to your subaccount.
To assign the role collection of the sample application to a user you have basically two options:

1. Navigate to the user by clicking on `Security` -> `Users`,
   select the user and click on `Assign Role Collection`
   (more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/find-users-and-their-role-collection-assignments)).
2. Navigate to the role collection by clicking on `Security` -> `Role Collections`,
   select `Sample Viewer (sap-java-buildpack-api-usage)`,
   click on `Edit` to add the user and finish by clicking on `Save`
   (more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/assign-users-to-role-collections)).
</details>

<details>
<summary>Assign role collection via command line</summary>

To assign the role collection to a user via the [btp CLI](https://help.sap.com/docs/btp/sap-business-technology-platform/account-administration-using-sap-btp-command-line-interface-btp-cli),
you need to [log in to your global account](https://help.sap.com/docs/btp/btp-cli-command-reference/btp-login) and execute the following command:

```shell
btp assign security/role-collection "Sample Viewer (sap-java-buildpack-api-usage)" --subaccount <subaccount id> --to-user <user email>
```
</details>

### 3. Access the application
The sample application provides a single HTTP endpoint:
- `/hello-token` - authorized access only

After the deployment, the application router will trigger authentication and [route requests](approuter/xs-app.json) to the above endpoint.
If you have assigned the role-collection as described above, you can access the application at:
```
https://approuter-sap-java-buildpack-api-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>
```
> Note: you can find the route of your approuter application using the cf CLI:
> ```
> cf app approuter-sap-java-buildpack-api-usage
> ```

You should see something like this:
```
Client ID: sap-java-buildpack-api-usage!t5721
Email: user@mail
Family Name: Jones
First Name: Bob
OAuth Grant Type: authorization_code
OAuth Token: eyJhbGciOiJSUzI1NiIsInR5...
```

### 4. Cleanup
If you no longer need the sample application, you can free up resources using the cf CLI.

```shell
cf delete -f sap-java-buildpack-api-usage
cf delete -f approuter-sap-java-buildpack-api-usage
cf delete-service -f xsuaa-buildpack
```
