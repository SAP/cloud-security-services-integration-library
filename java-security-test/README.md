# SAP CP Java Security Test Library

## Description
This library enhances the `java-security` project.
This includes for example a `JwtGenerator` that generates JSON Web Tokens (JWT) that can be used for JUnit tests, as well as for integration testing.

All of them are returned as [`Token`](/java-security/src/main/java/com/sap/cloud/security/token/Token.java), which offers you a `getAccessToken()` method that returns the encoded and signed Jwt token. You need to prefix this one with `Bearer ` in case you like to provide the access token via `Authorization` header to your application.

 > By default the generated token is Base64 encoded and signed with a RSA key.


## Requirements
- Java 8
- maven 3.3.9 or later

## Configuration

### Maven Dependencies
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>java-security-test</artifactId>
    <version>2.3.0-SNAPSHOT</version>
    <scope>test</scope>
</dependency>
```

## Usage
Find an example on how to use the test utilities [here](/samples/java-security-usage).

### Jwt Generator
```java
Token token = JwtGenerator.getInstance(Service.XSUAA)
                                .withHeaderParameter(TokenHeader.KEY_ID, "key-id")
                                .withClaim(TokenClaims.XSUAA.EMAIL, "tester@email.com")
                                .createToken();
```

### Servlet Test Utilities
The `SecurityIntegrationTestRule` uses third-party library [WireMock](http://wiremock.org/docs/getting-started/) to stub outgoing calls to the identity service. Furthermore it pre-configures the `JwtGenerator`, so that the token is signed with a private key which matches the public key provided by the jwks endpoint (on behalf of WireMock).

```java
public class HelloJavaServletTest {

	private static Properties oldProperties;

	@Rule
	public SecurityIntegrationTestRule rule = SecurityIntegrationTestRule.getInstance(XSUAA)
			.setPort(8181) // optionally overwrite WireMock port
			.useApplicationServer("src/test/webapp", 8282); // optionally overwrite app server port

	@BeforeClass
	public static void prepareTest() throws Exception {
		oldProperties = System.getProperties();
		System.setProperty("VCAP_SERVICES", IOUtils.resourceToString("/vcap.json", StandardCharsets.UTF_8));
	}

	@AfterClass
	public static void restoreProperties() {
		System.setProperties(oldProperties);
	}

	@Test
	public void requestWithoutHeader_statusUnauthorized() throws Exception {
		Token token = rule.createToken();

		HttpGet request = createGetRequest("Bearer " + token.getAccessToken());
		request.setHeader(HttpHeaders.AUTHORIZATION, null);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		}
	}

	@Test
	public void request_withValidToken() throws IOException {
		rule.getPreconfiguredJwtGenerator().withClaim(TokenClaims.XSUAA.EMAIL, "test.email@example.org");
		HttpGet request = createGetRequest("Bearer " + rule.createToken().getAccessToken());

		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
			assertThat(responseBody).contains("test.email@example.org");
		}
	}

	private HttpGet createGetRequest(String bearer_token) {
		HttpGet httpGet = new HttpGet(rule.getAppServerUri() + "/hello-java-security");
		httpGet.setHeader(HttpHeaders.AUTHORIZATION, bearer_token);
		return httpGet;
	}

}
```