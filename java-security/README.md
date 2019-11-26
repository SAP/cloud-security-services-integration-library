# SAP CP Java Security Library

A Java implementation of JSON Web Token (JWT) - RFC 7519 (see [1]). 

- Loads Identity Service Configuration from `VCAP_SERVICES` environment (`OAuth2ServiceConfiguration`) within SAP CP Cloud Foundry.
- Decodes and parses encoded access token (JWT) ([`XsuaaToken`](src/main/java/com/sap/cloud/security/token/XsuaaToken.java)) and provides access to token header parameters and claims.
- Validates the decoded token. The [`TokenValidatorBuilder`](
                                                           src/main/java/com/sap/cloud/security/token/validation/validators/TokenValidatorBuilder.java) comprises the following mandatory checks:
  - Is the jwt used before the "exp" (expiration) time and if it is used after the "nbf" (not before) time ([`JwtTimestampValidator`](
 src/main/java/com/sap/cloud/security/token/validation/validators/JwtTimestampValidator.java))?
  - Is the jwt issued by a trust worthy identity service ([`JwtIssuerValidator`](
 src/main/java/com/sap/cloud/security/token/validation/validators/JwtIssuerValidator.java))? In case of XSUAA does the token key url ("jku" jwt header parameter) match the identity service domain?
  - Is the jwt intended for the OAuth2 client of this application? The "aud" (audience) claim identifies the recipients the jwt is issued for ([`XsuaaJwtAudienceValidator`](
 src/main/java/com/sap/cloud/security/token/validation/validators/XsuaaJwtAudienceValidator.java)).
  - Is the jwt signed with the public key of the trust-worthy identity service? With that it also makes sure that the payload and the header of the jwt is unchanged ([`JwtSignatureValidator`](
 src/main/java/com/sap/cloud/security/token/validation/validators/JwtSignatureValidator.java))?
- Provides thread-local cache ([`SecurityContext`](src/main/java/com/sap/cloud/security/token/SecurityContext.java)) to store the decoded and validated token.

## Open Source libs used
- JSON Parser Reference implementation: [json.org](https://github.com/stleary/JSON-java)
- No crypto library. Leverages Public Key Infrastructure (PKI) provided by Java Security Framework to verify digital signatures.

## Supported Environments
- Cloud Foundry
- Planned: Kubernetes

## Supported Identity Services
- XSUAA
- Planned: IAS

## Supported Algorithms

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| RS256 | RSA256 | RSASSA-PKCS1-v1_5 with SHA-256 |


## Configuration

### Maven Dependencies
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>java-security</artifactId>
    <version>2.3.0</version>
</dependency>
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
    <version>2.3.0</version>
</dependency>
```

## Usage

### Setup: Load the Xsuaa Service Configurations 
```java
OAuth2ServiceConfiguration serviceConfig = Environments.getCurrentEnvironment().getXsuaaServiceConfiguration();
```
By default it auto-detects the environment: Cloud Foundry or Kubernetes.

### Per Request - 1: Create a Token Object 
This decodes an encoded access token (Jwt token) and parses its json header and payload. The `Token` interface provides a simple access to its jwt header parameters and its claims.

```java
String authorizationHeader = "Bearer eyJhbGciOiJGUzI1NiJ2.eyJhh...";
Token token = new XsuaaToken(authorizationHeader);
```

### Per Request - 2: Validate Access Token to check Authentication

```java
CombiningValidator<Token> combiningValidator = TokenValidatorBuilder.createFor(getXsuaaServiceConfiguration())
                                            .build();

ValidationResult result = combiningValidator.validate(token);

if(result.isErroneous()) {
   logger.warn("User is not authenticated: " + result.getErrorDescription());
}
```

By default the `TokenValidatorBuilder` bilds a `CombiningValidator` using the `DefaultOAuth2TokenKeyService` as `OAuth2TokenKeyService`, that uses an Apache Rest client to fetch the Json Web Token Keys. This can be customized via the `TokenValidatorBuilder` builder.

### Per Request - 3: Cache validated Access Token thread-locally
```java
SecurityContext.setToken(token);
```


### Get information from Access Token
```java
Token token = SecurityContext.getToken();

String email = token.getClaimAsString(TokenClaims.XSUAA.EMAIL);
List<String> scopes = token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
java.security.Principal principal = token.getPrincipal();
Instant expiredtAt = token.getExpiration();
...
```

## Sample
You can find a sample Servlet application [here](/samples/java-security-usage).

## Test Utilities
The `SecurityIntegrationTestRule` uses third-party library [WireMock](http://wiremock.org/docs/getting-started/) to stub outgoing calls to the identity service. Furthermore it pre-configures the JwtGenerator, so that the token is signed with a private key which matches the public key provided by the jwks endpoint (on behalf of WireMock).

### Maven Dependencies
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>java-security-test</artifactId>
    <version>${xsuaa.client.version}</version>
    <scope>test</scope>
</dependency>
```

### Jwt Generator
```java
Token token = JwtGenerator.getInstance(Service.XSUAA)
                                .withHeaderParameter(TokenHeader.KEY_ID, "key-id")
                                .withClaim(TokenClaims.XSUAA.EMAIL, "tester@email.com")
                                .createToken();
```

### Servlet Test Utilities
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

## Specs und References
1. [JSON Web Token](https://tools.ietf.org/html/rfc7519)
2. [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
3. [OpenID Connect Core 1.0 incorporating errata set 1 - ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
