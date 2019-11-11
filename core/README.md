# SAP CP Java Security Library

A Java implementation of JSON Web Token (JWT) - RFC 7519 (see [1]). 

- Loads Identity Service Configuration from `VCAP_SERVICES` environment (`OAuth2ServiceConfiguration`) within SAP CP Cloud Foundry.
- Decodes and parses encoded access token (JWT) (`TokenImpl`) and provides access to token header parameters and claims.
- Validates the decoded token. The `CombiningValidator` comprises the following mandatory checks:
  - Is the jwt used before the "exp" (expiration) time and if it is used after the "nbf" (not before) time (`JwtTimestampValidator`)?
  - Is the jwt issued by a trust worthy identity service (`JwtIssuerValidator`)? In case of XSUAA does the token key url ("jku" jwt header parameter) match the identity service domain?
  - Is the jwt intended for the OAuth2 client of this application? The "aud" (audience) claim identifies the recipients the jwt is issued for.
  - Is the jwt signed with the public key of the trust-worthy identity service? With that it also makes sure that the payload and the header of the jwt is unchanged (`JwtSignatureValidator`)?
- Provides thread-local cache to store the decoded and validated token (`SecurityContext`).

## Supported Environments
- Cloud FoundryT

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
OAuth2ServiceConfiguration serviceConfiguration = Environment.getXsuaaServiceConfiguration("CF");
```
By default it auto-detects the environment: Cloud Foundry or Kubernetes.

### Per Request - 1: Create a Token Object 
This decodes an encoded access token (Jwt token) and parses its json header and paylaod. The `Token` interface provides a simple access to its jwt header parameters and its claims.

```java
String authorizationHeader = "Bearer eyJhbGciOiJGUzI1NiJ2.eyJhh...";
Token token = new TokenImpl(authorizationHeader);
```

### Per Request - 2: Validate Access Token

```java
OAuth2ServiceConfiguration serviceConfig = Environment.getXsuaaServiceConfiguration("CF");
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


### Get Access Token from SecurityContext
```java
Token token = SecurityContext.getToken();
...
```

## Specs und references
1. [JSON Web Token](https://tools.ietf.org/html/rfc7519)
2. [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
3. [OpenID Connect Core 1.0 incorporating errata set 1 - ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
