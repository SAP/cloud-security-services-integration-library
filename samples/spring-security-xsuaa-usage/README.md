# Description
This sample uses the SAP application router as a web server and forwards requests to a Java Spring back-end application running on Cloud Foundry.
In a typcal UI5 application, the application router serves HTML files and REST data would be provided by a back-end application. To focus on the security part, UI5 has been omitted.

# Coding
This sample is using the spring-security project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. The security configuration needs to configure JWT for authentication.
Please see the [`spring-xsuaa` descriptions](../spring-xsuaa/README.md) for details.

# Deployment To Cloud Foundry or SAP HANA XS Advanced
To deploy the application, the following steps are required:
- Configure AppRouter
- Compile the Java application
- Create an XSUAA service instance
- Configure manifest.yml
- Deploy the application
- Access the application

## Download the Application Router

The [Application Router](./approuter/package.json) is used to provide a single entry point to a business application that consists of several different apps (microservices). It dispatches requests to backend microservices and acts as a reverse proxy. The rules that determine which request should be forwarded to which _destinations_ are called _routes_. The application router can be configured to authenticate the users and propagate the user information. Finally, the application router can serve static content.

## Compile the Java Application
Run maven to package the application
```shell
mvn clean package
```
## Create the XSUAA Service Instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a service instance
```shell
spring-security-xsuaa-usage$ cf create-service xsuaa application xsuaa-authentication -c xs-security.json
```
## Configuration the manifest
The [manifest-variables.yml](./manifest-variables.yml) contains hosts and paths that you might need to adopt.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file manifest-variables.yml
```

## Access the application
After deployment, the AppRouter will trigger authentication automatically when you access one of the following URLs:

* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v1/sayHello` - prints a welcome message, but only if token matches.
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v1/method` - executes a method secured with Spring Global Method Security.
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v1/readData` - reads data via Global Method Security.
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v1/writeData` - writes data via Global Method Security.
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v1/clientCredentialsToken` - executes a Client Credentials Token flow.
* `https://spring-security-xsuaa-usage-web-<ID>.<LANDSCAPE_APPS_DOMAIN>/v1/printXsuaaBindingInformation` - prints the XSUAA service binding information from the environment.

## Locally Running the Application

The application can be run locally, but in order to do so, you need the XSUAA binding information in the application's environment. Using tools like Eclipse of IntelliJ Idea this is easy. But there is also an easier way:

Simply rename the `_vcap-services.json` file in `src/main/resources` to `vcap-services.json` and dump your `VCAP_SERVICES` from Cloud Foundry in the file. `spring-xsuaa` will pick up the file, if it is present and load the environment from there.
