# Description
This sample uses the SAP Approuter as web server and forwards requests to a Java backend application running on the SAP Java buildpack.
In a typcal UI5 application, the approuter would server HTML files and REST data would be provided by a backend application. To focus on the security part, UI5 has been omitted.

# Coding
The web.xml of the application must use auth-method with value XSUAA. This enables authentication of requests using incoming OAuth authentication tokens.

```xml
<web-app>
<display-name>sample</display-name>
  <login-config> 
    <auth-method>XSUAA</auth-method>
  </login-config> 
</web-app> 
```

In the Java coding, use the @ServletSecurity annotations:
```java
package com.sap.cloud.security.xssec.samples.sapbuildpack;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sap.xsa.security.container.XSUserInfo;
import com.sap.xsa.security.container.XSUserInfoException;

/**
 * Servlet implementation class HelloTokenServlet
 */
@WebServlet("/hello-token")

// configure servlet to check against scope "$XSAPPNAME.Display"
@ServletSecurity(@HttpConstraint(rolesAllowed = { "Display" }))
public class HelloTokenServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		response.setContentType("text/plain");
		XSUserInfo userInfo = (XSUserInfo) request.getUserPrincipal();

		try {
			response.getWriter().append("Client ID: ").append("" + userInfo.getClientId());
			response.getWriter().append("\n");
			response.getWriter().append("Email: ").append("" + userInfo.getEmail());
			response.getWriter().append("\n");
			response.getWriter().append("Family Name: ").append("" + userInfo.getFamilyName());
			response.getWriter().append("\n");
			response.getWriter().append("First Name: ").append("" + userInfo.getGivenName());
			response.getWriter().append("\n");
			response.getWriter().append("OAuth Grant Type: ").append("" + userInfo.getGrantType());
			response.getWriter().append("\n");
			response.getWriter().append("OAuth Token: ").append("" + userInfo.getAppToken());
			response.getWriter().append("\n");

		} catch (XSUserInfoException e) {
			e.printStackTrace(response.getWriter());
		}
	}
}
```
# Deployment on Cloud Foundry or SAP HANA Advanced
To deploy the application, the following steps are required:
- Download the approuter
- Compile the Java application
- Create a xsuaa service instance
- Configure the manifest
- Deploy the application
- Access the application
## Download the approuter
The [Application Router](./approuter/package.json) is used to provide a single entry point to a business application that consists of several different apps (microservices). It dispatches requests to backend microservices and acts as a reverse proxy. The rules that determine which request should be forwarded to which _destinations_ are called _routes_. The application router can be configured to authenticate the users and propagate the user information. Finally, the application router can serve static content.
*  Run `npm install`

```shell
    approuter$ npm config set @sap:registry https://npm.sap.com
    approuter$ npm install @sap/approuter
```
## Compile the Java application
Run maven to package the application
```shell
sap-java-buildpack-api-usage$ mvn package
```
## Create the xsuaa service instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a service instance
```shell
sap-java-buildpack-api-usage$ cf create-service xsuaa application xsuaa-authentication -c xs-security.json
```
## Configuration the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
sap-java-buildpack-api-usage$ cf push --vars-file ../vars.yml
```

## Access the application
After deployment, the application router will trigger authentication. If you have assigned the role provided in the xs-security.json to your user, you will see an output like:
```
Client ID: sap-java-buildpack-api-usage!t5721
Email: user@mail
Family Name: Jones
First Name: Bob
OAuth Grant Type: authorization_code
OAuth Token: eyJhbGciOiJSUzI1NiIsInR5...
```


