# SAP CP Java Security Test Library

## Description
This library complements the `java-security` project with testing utilities.
It includes for example a `JwtGenerator` that generates JSON Web Tokens (JWT) that can be used for JUnit tests, as well as for integration testing.

 > By default the generated token is Base64 encoded and signed with a generated RSA key.


## Requirements
- Java 8
- maven 3.3.9 or later
- JUnit 4, 5

> If you use spring-boot-starter-test, you might be facing json classpath issues. See the [Issues](#Issues)
> section for more information.

## Configuration

### Maven Dependencies
```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-security-test</artifactId>
    <version>2.6.2</version>
    <scope>test</scope>
</dependency>
```

## Usage
Find an example on how to use the test utilities [here](/samples/java-security-usage).

### Jwt Generator
Using `JwtGenerator` you can create tokens of type [`Token`](/java-security/src/main/java/com/sap/cloud/security/token/Token.java), which offers you a `getTokenValue()` method that returns the encoded and signed Jwt token. By default its signed with a random RSA key pair. In case you like to provide the token via `Authorization` header to your application you need to prefix the access token with `Bearer `. 

```java
Token token = JwtGenerator.getInstance(Service.XSUAA)
                                .withHeaderParameter(TokenHeader.KEY_ID, "key-id") // optional
                                .withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId) // optional
                                .createToken();

String authorizationHeaderValue = 'Bearer ' + token.getTokenValue();
```

### Unit Test Utilities
In case you want to test your secured web application as part of your JUnit tests you need to generate JWT tokens and in order to validate the token you need also to mock the jwks endpoint of the identity service e.g. xsuaa. 

The `java-security-test` library uses third-party library [WireMock](http://wiremock.org/docs/getting-started/) to stub outgoing calls to the identity service. Furthermore it pre-configures the `JwtGenerator`, so that the token is signed with a private key which matches the public key provided by the jwks endpoint (on behalf of WireMock). Furthermore you can specify the `clientId` for token generation, that it can be validated by the predefined set of Jwt validators.

Optionally, you can configure `java-security-test` to start an embedded Jetty servlet container that comes equipped with an [authenticator](src/main/java/com/sap/cloud/security/servlet/XsuaaTokenAuthenticator.java). The authenticator checks whether a request is done by an authenticated AND authorized party. You can also add your own servlets to the container. Only requests that contain a valid authorization header will be passed through to the servlet. See the following test code that triggers HTTP requests against the servlet container. One request does not contain the token inside the authorization header and is expected to result in HTTP `401` (unauthenticated). The other contains a valid token and is expected to succeed.


#### JUnit 4
Use `SecurityTestRule`, which is an `ExternalResource` that set up `WireMock` and optionally the Jetty servlet container before a test, and guarantee to tear it down afterward.

```java
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.token.TokenClaims.*;

public class HelloJavaServletTest {
    
	private static Properties oldProperties;

	@ClassRule
	public static SecurityTestRule rule = SecurityTestRule.getInstance(Service.XSUAA)
			.useApplicationServer() // optionally customize application server, e.g. port
			.addApplicationServlet(TestServlet.class, "/hi");  // add servlet to be tested to application server
    
	@After
	public void tearDown() {
		SecurityContext.clearToken();
	}

	@Test
	public void requestWithoutAuthorizationHeader_unauthenticated() throws IOException {
		HttpGet request = createGetRequest(null);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
		}
	}

	@Test
	public void requestWithValidToken_ok() throws IOException {
		String jwt = rule.getPreconfiguredJwtGenerator()
				.withScopes("openid")
				.withLocalScopes("Read") // SecurityTestRule.DEFAULT_APP_ID + ".Read"
				.createToken()
				.getTokenValue();
		HttpGet request = createGetRequest(jwt);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
		}
	}

	private HttpGet createGetRequest(String accessToken) {
		HttpGet httpGet = new HttpGet(rule.getApplicationServerUri() + HelloJavaServlet.ENDPOINT);
		if(accessToken != null) {
			httpGet.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
		}
		return httpGet;
	}
}
```
#### JUnit 5
JUnit 5 does no longer support `Rule`. You can configure a static `SecurityTest` instance. The `setup` method starts `WireMock` and optionally the Jetty servlet container, if not yet running. Furthermore, it resets `WireMock` and reconfigures the stubs. Finally, call the `tearDown` method to stop the running server(s):

```java
public class HelloJavaTest {

	private static SecurityTest securityTest = new SecurityTest(Service.XSUAA);
	
	@BeforeEach
	public void setup() throws Exception {
		securityTest.setup();
	}

	@AfterAll
	public static void tearDown() {
		securityTest.tearDown();
	}

	@Test
	public void v1_sayHello() throws Exception {
		String jwt = securityTest.getPreconfiguredJwtGenerator()
						.withLocalScopes("Read")
						.createToken().getTokenValue();
		// call endpoint with Authorization header "Bearer <jwt>" 			
		...
	}
}
```

## Issues

This module requires the [JSON-Java](https://github.com/stleary/JSON-java) library.
If you have classpath related  issues involving JSON you should take a look at the
[Troubleshooting JSON class path issues](/docs/Troubleshooting_JsonClasspathIssues.md) document.

## Samples
The `java-security-test` library is used in the following samples:
- [java-security-usage](/samples/java-security-usage)
- [spring-security-xsuaa-usage](/samples/spring-security-xsuaa-usage)
