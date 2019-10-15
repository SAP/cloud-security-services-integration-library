# Description
This sample uses the SAP application router as a web server and forwards requests to a Java back-end application running
on the SAP Java buildpack. On incoming requests it reads credentials from the `VCAP_SERVICES` environment variable and
requests a new access token via client credentials token flow provided by the [Token Client](../../token-client/)
library.

In a typcal UI5 application, the application router server HTML files and REST data would be provided by a 
back-end application. To focus on the security part, UI5 has been omitted.

# Coding
The [web.xml](src/main/webapp/WEB-INF/web.xml) of the application must use auth-method with value XSUAA. 
This enables authentication of requests using incoming OAuth authentication tokens.

```xml
<web-app>
<display-name>sample</display-name>
  <login-config> 
    <auth-method>XSUAA</auth-method>
  </login-config> 
</web-app> 
```

In the Java coding, use the `@ServletSecurity` annotations:
```java
import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/hello-tokenflow")
@ServletSecurity(@HttpConstraint(rolesAllowed = { "Display" }))
public class HelloTokenFlowServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 * response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		response.setContentType("text/plain");

		JSONObject jsonObject = createJsonObjectFromVCAPServices();
		String clientSecret = extractString(jsonObject, "/xsuaa/0/credentials/clientsecret");
		String clientid = extractString(jsonObject, "/xsuaa/0/credentials/clientid");
		String url = extractString(jsonObject, "/xsuaa/0/credentials/url");

		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
				new DefaultOAuth2TokenService(),
				new XsuaaDefaultEndpoints(url), new ClientCredentials(clientid, clientSecret));
		OAuth2TokenResponse tokenResponse = tokenFlows.clientCredentialsTokenFlow().execute();

		writeLine(response, "Access-Token: " + tokenResponse.getAccessToken());
		writeLine(response, "Expired-At: " + tokenResponse.getExpiredAtDate());
	}

	private String extractString(JSONObject jsonObject, String jsonPointer) {
		return jsonObject.query(jsonPointer).toString();
	}

	private JSONObject createJsonObjectFromVCAPServices() {
		String vcapServices = System.getenv("VCAP_SERVICES");
		return new JSONObject(vcapServices);
	}

	private void writeLine(HttpServletResponse response, String string) throws IOException {
		response.getWriter().append(string);
		response.getWriter().append("\n");
	}

}
```

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
cf create-service xsuaa application xsuaa-tokenflow -c xs-security.json
```

## Configuration the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Cockpit administration tasks: Assign Role to your User
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection(s) such as `Tokenflow_Buildpack_API_Viewer` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on sap.help.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).

## Access the application
After deployment, the application router will trigger authentication. If you have assigned the role-collection provided in the [xs-security.json](./xs-security.json) to your user, you will see an output like when calling `https://approuter-sap-java-buildpack-tokenflow-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>`:

```
Access-Token: eyJhbGciOiJSUzI1NiIsImprdSI6I...
Expired-At: Tue Oct 15 02:55:27 UTC 2019
```
If not you should get a `403` status code (Forbidden).

> Note: you can find the route of your approuter application using `cf app approuter-sap-java-buildpack-tokenflow-usage`.

## Clean-Up

Finally delete your application and your service instances using the following commands:
```
cf delete -f sap-java-buildpack-tokenflow-usage
cf delete -f approuter-sap-java-buildpack-tokenflow-usage
cf delete-service -f xsuaa-tokenflow
```
