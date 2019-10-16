# Description
This sample is a Java back-end application running on the Cloud Foundry Java buildpack. On incoming requests it reads 
credentials from the `VCAP_SERVICES` environment  variable and requests a new access token via client credentials token
flow provided by the [Token Client](../../token-client/) library.

# Coding

The following java code shows the implementation of the `HttpServlet` that handles the incoming HTTP requests.
```java
package com.sap.cloud.security.xssec.samples.tokenflow.usage;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/hello-tokenflow")
public class HelloTokenFlowServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 * response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
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
		writeLine(response, "Access-Token-Payload: " + tokenResponse.getDecodedAccessToken().getPayload());
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
- Compile the Java application
- Create a xsuaa service instance
- Configure the manifest
- Deploy the application
- Access the application

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

## Access the application
To access the application go to `https://java-buildpack-tokenflow-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/hello-tokenflow`
You should see something like this:
```
Access-Token: eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vYzUyOTU0MDB0cmlhbC5hdXRoZW50aWN...
Access-Token-Payload: {"jti":"a2ea5313e37345709985836b1400305f","ext_attr":{"enhancer":"XSUAA","zdn":"c5295400trial"},...
Expired-At: Wed Oct 16 13:37:00 UTC 2019
```

## Clean-Up

Finally delete your application and your service instances using the following commands:
```
cf delete -f java-buildpack-tokenflow-usage
cf delete-service -f xsuaa-tokenflow
```
