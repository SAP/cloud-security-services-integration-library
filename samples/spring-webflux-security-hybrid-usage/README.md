# SAP BTP Spring Security Client Library Webflux sample application
This Spring Boot sample application is build with the `spring-webflux` framework and is protected by the
`spring-security-oauth2-resource-server`.
It uses the `spring-security` module to validate JWT tokens issued by either the `xsuaa` or the `identity` service.
The `xsuaa` service provides an OAuth access token, while the `identity` service provides an OIDC token.
The tokens differ in the details they provide through token claims.
In both instances, the validated token is accessible as a [`Token`](/java-api/src/main/java/com/sap/cloud/security/token/Token.java) via the `ReactiveSecurityContext`.

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
cf create-service xsuaa application xsuaa-webflux -c xs-security.json
```
#### Create the IAS service instance
```shell
cf create-service identity application ias-webflux -c ias-security.json
```
:bulb: You may need to adapt the hostname in the [ias config](ias-security.json).

#### Configure the manifest
The [vars](../vars.yml) contain hosts and paths that need to be adapted.

#### Deploy the application
Deploy the application using the cf CLI.

```shell
cf push --vars-file ../vars.yml
```
:warning: This will expect 1 GB of free memory quota.

### 3. Give permission to user
To get access to the sample application, you need a user with one of the following assigned:
- the role collection `Sample Viewer (spring-webflux-security-hybrid-usage)' (via XSUAA)
- the group `Read` (via IAS)

#### Assign Role Collection (XSUAA)
This can be done in the SAP BTP Cockpit or using the btp CLI.

<details>
<summary>Assign role collection via cockpit</summary>
In the cockpit navigate to your subaccount.
To assign the role collection of the sample application to a user you have basically two options:

1. Navigate to the user by clicking on `Security` -> `Users`,
   select the user and click on `Assign Role Collection`
   (more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/find-users-and-their-role-collection-assignments)).
2. Navigate to the role collection by clicking on `Security` -> `Role Collections`,
   select `Sample Viewer (spring-webflux-security-hybrid-usage)`,
   click on `Edit` to add the user and finish by clicking on `Save`
   (more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/assign-users-to-role-collections)).
</details>

<details>
<summary>Assign role collection via command line</summary>

To assign the role collection to a user via the [btp CLI](https://help.sap.com/docs/btp/sap-business-technology-platform/account-administration-using-sap-btp-command-line-interface-btp-cli),
you need to [log in to your global account](https://help.sap.com/docs/btp/btp-cli-command-reference/btp-login) and execute the following command:

```shell
btp assign security/role-collection "Sample Viewer (spring-webflux-security-hybrid-usage)" --subaccount <subaccount id> --to-user <user email>
```
</details>

#### Assign group (IAS)
You need administrator permissions to create group `Read` in IAS and assign it to a user.
:link: More information can be found at [SAP Help: "Creating a User Group"](https://help.sap.com/viewer/a339f23ec736441abb2e187b7a7b6afb/LATEST/en-US/64544f432cd24b8589707a5d8a2b3e2e.html).

### 3. Access the application
The sample application provides a single HTTP endpoint:
- `/v1/sayHello` - authorized access only

After the deployment, the application router will trigger authentication and [route requests](approuter/xs-app.json) to the above endpoint.
If you have assigned the role-collection as described above, you can access the application via XSUAA at:
```
https://spring-webflux-security-hybrid-usage-web-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/xsuaa/sayHello
```
If you have assigned the group as described above, you can access the application via IAS at:
```
https://spring-webflux-security-hybrid-usage-web-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/ias/sayHello
```
:bulb: you can find the route of your approuter application using the cf CLI:
```
cf app approuter-spring-webflux-security-hybrid-usage
```

You should see the JSON payload of the received JWT token.
:warning: In order to switch between XSUAA and IAS access, you need to remove any `Application Access Tokens` from your profile page in th ecorresponding IAS tenant.
Furthermore, you want to delete any account related cookies in your browser or use a private browser window.

### 4. Cleanup
If you no longer need the sample application, you can free up resources using the cf CLI.

```shell
cf unbind-service spring-webflux-security-hybrid-usage ias-webflux
cf unbind-service approuter-spring-webflux-security-hybrid-usage ias-webflux
cf delete -f spring-webflux-security-hybrid-usage
cf delete -f approuter-spring-webflux-security-hybrid-usage
cf delete-service -f xsuaa-webflux
cf delete-service -f ias-webflux
```
