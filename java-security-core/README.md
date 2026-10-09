# SAP BTP Java Security Core Client Library

The core part of the SAP BTP Java Security client library: token model, JWT validation and
X.509 helpers — **without any `jakarta.servlet` or Spring dependency**.

This module exists so that token validation can be used from non-Jakarta environments
(e.g. Tomcat 9 / `javax.servlet` runtimes) and from non-servlet code (batch jobs,
message-driven components, custom filters).

## What's in this module

| Package | Content |
|---|---|
| `com.sap.cloud.security.token` | Token model (`Token`, `XsuaaToken`, `SapIdToken`, `IdTokenExtension`, `ScopeConverter`, `TokenExchangeMode`), thread-local `SecurityContext` token cache |
| `com.sap.cloud.security.token.validation` | `Validator`, `CombiningValidator`, `ValidationResult(s)`, `ValidationListener` |
| `com.sap.cloud.security.token.validation.validators` | `JwtValidatorBuilder` and all JWT validators (signature, issuer, audience, timestamp, `X5t` / proof token, JWKS handling with cache) |
| `com.sap.cloud.security.x509` | X.509 certificate helpers (`X509Certificate`, thumbprints) |
| `com.sap.cloud.security.servlet` | `HybridTokenFactory` only — the `TokenFactory` ServiceLoader registration used by `Token.create()`. Despite the package name it has **no servlet dependency** (historical package, kept for compatibility) |

The servlet-based token authenticators (`HybridTokenAuthenticator`, `IasTokenAuthenticator`,
`XsuaaTokenAuthenticator`) and the Spring security context adapter
(`com.sap.cloud.security.adapter.spring`) live in the
[`java-security`](../java-security) module, which depends on this module. If you depend on
`java-security` you get everything transitively — no code changes needed.

## Maven

```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-security-core</artifactId>
    <version>4.1.2</version>
</dependency>
```

## Usage

Token validation without a servlet context:

```java
// 1. Service configuration (Cloud Foundry VCAP / Kubernetes secrets) or built manually
OAuth2ServiceConfiguration xsuaaConfig = Environments.getCurrent().getXsuaaConfiguration();

// 2. Build the validator chain (XSUAA or IAS, with audience/JWKs cache as needed)
Validator<Token> validator = JwtValidatorBuilder.getInstance(xsuaaConfig)
        .withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofMinutes(30), 100, true))
        .build();

// 3. Validate the token from the Authorization header
Token token = Token.create("Bearer <access_token>");
ValidationResults results = validator.validate(token);
```

This is exactly what `HybridTokenAuthenticator` does internally in the `java-security`
module; with `java-security-core` you drive the same validators directly and extract the
Authorization header yourself from your (javax) servlet request.

## Requirements

- Java 17
- Service configuration via Cloud Foundry (`VCAP_SERVICES`) or Kubernetes/Kyma secrets
  (see [`env`](../env) module), or a manually constructed `OAuth2ServiceConfiguration`

## Supported Identity Services & Algorithms

See the [java-security README](../java-security) — this module contains the same
validators, so supported identity services (XSUAA, SAP Identity) and token signature
algorithms are identical.
