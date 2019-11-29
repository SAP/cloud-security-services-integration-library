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

### Setup: Load the Xsuaa Service Configurations and setup Validator
```java
OAuth2ServiceConfiguration serviceConfig = Environments.getCurrentEnvironment().getXsuaaServiceConfiguration();
CombiningValidator<Token> validators = TokenValidatorBuilder.createFor(serviceConfig).build();
```
By default it auto-detects the environment: Cloud Foundry or Kubernetes.

### Create a Token Object 
This decodes an encoded access token (Jwt token) and parses its json header and payload. The `Token` interface provides a simple access to its jwt header parameters and its claims.

```java
String authorizationHeader = "Bearer eyJhbGciOiJGUzI1NiJ2.eyJhh...";
Token token = new XsuaaToken(authorizationHeader);
```

### Validate Access Token to check Authentication

```java
ValidationResult result = validators.validate(token);

if(result.isErroneous()) {
   logger.warn("User is not authenticated: " + result.getErrorDescription());
}
```

By default the `TokenValidatorBuilder` builds a `CombiningValidator` using the `DefaultOAuth2TokenKeyService` as `OAuth2TokenKeyService`, that uses an Apache Rest client to fetch the Json Web Token Keys. This can be customized via the `TokenValidatorBuilder` builder.

### Cache validated Access Token (thread-locally)
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
You can find the test utilites documented [here](/java-security-test).

## Specs und References
1. [JSON Web Token](https://tools.ietf.org/html/rfc7519)
2. [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
3. [OpenID Connect Core 1.0 incorporating errata set 1 - ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
