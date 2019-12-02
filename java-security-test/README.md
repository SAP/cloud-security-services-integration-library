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
Using `JwtGenerator` you can create tokens of type [`Token`](/java-security/src/main/java/com/sap/cloud/security/token/Token.java) that are by default signed with a random RSA key pair.  
```java
Token token = JwtGenerator.getInstance(Service.XSUAA)
                                .withHeaderParameter(TokenHeader.KEY_ID, "key-id") // optional
                                .withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId) // optional
                                .createToken();
```

### Unit Test Utilities
In case you want to test your secured web application as part of your JUnit tests you need to generate jwt tokens and in order to validate the token you need also to mock the jwks endpoint of the identity service. 

The `SecurityIntegrationTestRule` uses third-party library [WireMock](http://wiremock.org/docs/getting-started/) to stub outgoing calls to the identity service. Furthermore it pre-configures the `JwtGenerator`, so that the token is signed with a private key which matches the public key provided by the jwks endpoint (on behalf of WireMock). Furthermore you can specify the `clientId` for token generation, that it can be validated by the predefined set of Jwt validators.

Optionally, you can configure the `SecurityIntegrationTestRule` to start an embedded Tomcat servlet container which then needs to be configured with the Security Filter, that is in place to check whether a request is done by an authenticated / authorized party ([example `web.xml`](/samples/java-security-usage/src/test/webapp/WEB-INF/web.xml)).
 

```java
public class HelloJavaServletTest {

	private static Properties oldProperties;

	@ClassRule
	public SecurityIntegrationTestRule rule = SecurityIntegrationTestRule.getInstance(XSUAA)
			.setPort(8181) // optionally overwrite WireMock port
			.useApplicationServer("src/test/webapp", 8282); // optionally overwrite app server port

	@BeforeClass
	public static void prepareTest() throws Exception {
		oldProperties = System.getProperties();
		System.setProperty("VCAP_SERVICES", IOUtils.resourceToString("/vcap.json", StandardCharsets.UTF_8));
        rule.setClientId(Environments.getCurrent().getXsuaaServiceConfiguration().getClientId());
	}

	@AfterClass
	public static void restoreProperties() {
		System.setProperties(oldProperties);
	}

	@Test
    public void requestWithoutAuthorizationHeader_statusUnauthenticated() throws IOException {
        HttpGet request = createGetRequest(null);
        try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
            assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
        }
    }

    @Test
    public void requestWithEmptyAuthorizationHeader_statusUnauthenticated() throws Exception {
        HttpGet request = createGetRequest("");
        try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
            assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
        }
    }

    @Test
    public void request_withValidToken() throws IOException {
        HttpGet request = createGetRequest(rule.createToken().getBearerAccessToken());

        try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
            String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
        }
    }

    private HttpGet createGetRequest(String bearerToken) {
		HttpGet httpGet = new HttpGet(rule.getAppServerUri() + HelloJavaServlet.ENDPOINT);
		if(bearerToken != null) {
			httpGet.setHeader(HttpHeaders.AUTHORIZATION, bearerToken);
		}
		return httpGet;
	}

}
```