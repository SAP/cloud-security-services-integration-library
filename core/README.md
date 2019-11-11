# SAP CP Java Security Library

A Java implementation of JSON Web Token (JWT) - RFC 7519 (see [1]). 

- Loads Identity Service Configuration from `VCAP_SERVICES` environment (`OAuth2ServiceConfiguration`) within SAP CP Cloud Foundry.
- Decodes and parses encoded access token (JWT) ([`TokenImpl`](src/main/java/com/sap/cloud/security/token/TokenImpl.java)) and provides access to token header parameters and claims.
- Validates the decoded token. The `CombiningValidator` comprises the following mandatory checks:
  - Is the jwt used before the "exp" (expiration) time and if it is used after the "nbf" (not before) time ([`JwtTimestampValidator`](
 src/main/java/com/sap/cloud/security/token/validation/validators/JwtTimestampValidator.java))?
  - Is the jwt issued by a trust worthy identity service ([`JwtIssuerValidator`](
 src/main/java/com/sap/cloud/security/token/validation/validators/JwtIssuerValidator.java))? In case of XSUAA does the token key url ("jku" jwt header parameter) match the identity service domain?
  - Is the jwt intended for the OAuth2 client of this application? The "aud" (audience) claim identifies the recipients the jwt is issued for ([`XsuaaJwtAudienceValidator`](
 src/main/java/com/sap/cloud/security/token/validation/validators/XsuaaJwtAudienceValidator.java)).
  - Is the jwt signed with the public key of the trust-worthy identity service? With that it also makes sure that the payload and the header of the jwt is unchanged ([`JwtSignatureValidator`](
 src/main/java/com/sap/cloud/security/token/validation/validators/JwtSignatureValidator.java))?
- Provides thread-local cache ([`SecurityContext`](src/main/java/com/sap/cloud/security/token/SecurityContext.java)) to store the decoded and validated token.

## Supported Environments
- Cloud Foundry

## Supported Identity Services
- XSUAA

## Supported Algorithms

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| RS256 | RSA256 | RSASSA-PKCS1-v1_5 with SHA-256 |


## Configuration

### Maven Dependencies
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>core</artifactId>
    <version>2.3.0</version>
</dependency>
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
    <version>2.3.0</version>
</dependency>
```

## Usage

### Setup: Loads the Xsuaa Service Configurations 
```java
OAuth2ServiceConfiguration serviceConfig = Environment.getInstance().getXsuaaServiceConfiguration();
```
By default it auto-detects the environment: Cloud Foundry or Kubernetes.

### Per Request - 1: Create a Token Object 
This decodes an encoded access token (Jwt token) and parses its json header and payload. The `Token` interface provides a simple access to its jwt header parameters and its claims.

```java
String authorizationHeader = "Bearer eyJhbGciOiJGUzI1NiJ2.eyJhh...";
Token token = new TokenImpl(authorizationHeader);
```

### Per Request - 2: Validate Access Token to check Authentication

```java
CombiningValidator combiningValidator = CombiningValidator.builderFor(serviceConfiguration).build();

ValidationResult result = combiningValidator.validate(token);

if(result.isErronous()) {
   logger.error("User is not authenticated: " + result.getErrorDescription());
}
```

By default the `CombiningValidator` uses the `DefaultOAuth2TokenKeyService` as `OAuth2TokenKeyService` that uses an Apache Rest client to fetch the Json Web Token Keys. This can be customized via the `CombiningValidator` builder.

### Per Request - 3: Cache validated Access Token thread-locally
```java
SecurityContext.setToken(token);
```


### Get information from Access Token
```java
Token token = SecurityContext.getToken();

String email = token.getClaimAsString(TokenClaims.XSUAA.EMAIL);
List<String> scopes = token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
...
```

## Sample
You can find a sample Servlet application [here](/samples/java-security-usage).

## Specs und references
1. [JSON Web Token](https://tools.ietf.org/html/rfc7519)
2. [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
3. [OpenID Connect Core 1.0 incorporating errata set 1 - ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
