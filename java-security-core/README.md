# SAP BTP Java Security Core Client Library

The core part of the SAP BTP Java Security client library: token model, JWT validation and
X.509 helpers — **without any `jakarta.servlet` or Spring dependency**.

## Why does this module exist?

Since version 4.3.0 the `java-security` artifact is split into two modules:

- **`java-security-core` (this module)** — the token model, all JWT validators and the X.509
  helpers. No `jakarta.servlet`, no Spring.
- [`java-security`](../java-security) — the servlet-based authenticators
  (`HybridTokenAuthenticator`, `IasTokenAuthenticator`, `XsuaaTokenAuthenticator`) and the
  Spring security context adapter. Depends on `java-security-core`.

Token validation itself never needed a servlet container — but before the split it was only
reachable through a module that pulled the Jakarta EE servlet API into your classpath. With the
split, `java-security-core` can be used from:

- **`javax.servlet` runtimes (e.g. Tomcat 9 / older buildpacks)** where putting `jakarta.*`
  APIs on the classpath is not an option
- **non-servlet code** — batch jobs, message listeners, CLI tools, custom filters
- **any environment where you want the minimal footprint** (no servlet API, no Spring)

**No API or behavior change for existing `java-security` consumers.** All moved classes keep
their fully qualified names and stay on your classpath transitively via `java-security`.

## What's in this module

| Package | Content |
|---|---|
| `com.sap.cloud.security.token` | Token model (`Token`, `XsuaaToken`, `SapIdToken`, `IdTokenExtension`, `ScopeConverter`, `TokenExchangeMode`), thread-local `SecurityContext` token cache |
| `com.sap.cloud.security.token.validation` | `Validator`, `CombiningValidator`, `ValidationResult(s)`, `ValidationListener` |
| `com.sap.cloud.security.token.validation.validators` | `JwtValidatorBuilder` and all JWT validators (signature, issuer, audience, timestamp, `X5t` / proof token, JWKS handling with cache) |
| `com.sap.cloud.security.x509` | X.509 certificate helpers (`X509Certificate`, thumbprints) |
| `com.sap.cloud.security.servlet` | `HybridTokenFactory` only — the `TokenFactory` ServiceLoader registration used by `Token.create()`. Despite the package name it has **no servlet dependency** (historical package, kept for compatibility) |

## Maven

```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-security-core</artifactId>
    <version>4.3.0</version>
</dependency>
```

## Usage

Token validation without a servlet context:

```java
// 1. Service configuration (Cloud Foundry VCAP / Kubernetes secrets) or built manually
OAuth2ServiceConfiguration xsuaaConfig = Environments.getCurrent().getXsuaaConfiguration();

// 2. Build the validator chain (XSUAA or IAS, with audience/JWKs cache as needed)
Validator<Token> validator = JwtValidatorBuilder.getInstance(xsuaaConfig)
        .withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofMinutes(30), 1000, false))
        .build();

// 3. Validate the token from the Authorization header
Token token = Token.create("Bearer <access_token>");
ValidationResult result = validator.validate(token);
```

This is exactly what `HybridTokenAuthenticator` does internally in the `java-security`
module; with `java-security-core` you drive the same validators directly and extract the
Authorization header yourself from your (javax) servlet request.

## Building your own Authenticator

The ready-made `*TokenAuthenticator` classes in `java-security` are thin wrappers around the
validators in this module. When they do not fit your needs — a different entry point, a custom
filter, a non-Jakarta runtime, or extra checks on top of the standard ones — you compose the
same building blocks yourself:

### 1. Build the validator chain

`JwtValidatorBuilder` assembles the standard chain for the given service configuration
(timestamp, audience, and signature validators for XSUAA; issuer, signature and audience
validation for Identity service). One instance is kept per configuration (singleton semantics).

```java
OAuth2ServiceConfiguration config = Environments.getCurrent().getXsuaaConfiguration();

Validator<Token> validator = JwtValidatorBuilder.getInstance(config)
        .withHttpClient(httpClient) // for JWKS retrieval; obtain via SecurityHttpClientProvider
        .withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(
                Duration.ofMinutes(10), 1000, false)) // JWKS cache tuning
        .build();
```

### 2. Add, replace or extend the validators

`Validator<T>` is a plain interface; `build()` returns a `CombiningValidator` that runs all
registered validators and aggregates their results. The builder offers hooks for the common
customizations:

```java
Validator<Token> validator = JwtValidatorBuilder.getInstance(config)
        .with(new MyCustomClaimValidator())          // register your own validator
        .withAudienceValidator(customAudience)       // replace the default audience check
        .with(new JwtX5tValidator(config))           // add the mTLS thumbprint (RFC 8705) check
        .enableProofTokenCheck()                     // Identity service: proof-token validation
        .withValidatorListener(auditListener)        // callback for audit logging
        .configureAnotherServiceInstance(otherConfig) // also accept tokens from a 2nd instance
        .build();
```

A custom validator is just a class implementing `Validator<Token>`:

```java
public final class MyCustomClaimValidator implements Validator<Token> {

    @Override
    public ValidationResult validate(final Token token) {
        if (token.getClaimAsString("my_required_claim") == null) {
            return ValidationResults.createInvalid("Missing required claim 'my_required_claim'");
        }
        return ValidationResults.createValid();
    }
}
```

Keep the default validators in place unless you have a concrete reason to replace them —
they implement the security-critical checks (signature, issuer, audience, expiration).

### 3. Drive it from your entry point

In a `javax.servlet` filter (the Jakarta variant is identical, only the `javax`/`jakarta`
package names differ):

```java
@WebFilter("/*")
public class MySecurityFilter implements Filter {

    private final Validator<Token> validator = ...; // built once — thread-safe

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {
            String authHeader = ((HttpServletRequest) request).getHeader("Authorization");
            Token token = Token.create(authHeader); // parses "Bearer <jwt>"
            ValidationResult result = validator.validate(token);

            if (result.isValid()) {
                SecurityContext.setToken(token); // make the token available to your code
                chain.doFilter(request, response);
            } else {
                ((HttpServletResponse) response)
                        .sendError(HttpServletResponse.SC_UNAUTHORIZED, result.getErrorDescription());
            }
        } finally {
            SecurityContext.clear();
        }
    }
}
```

That is the full pattern — the same validation logic as the shipped authenticators, without
any servlet-API dependency from this library.

## Requirements

- Java 17
- Service configuration via Cloud Foundry (`VCAP_SERVICES`) or Kubernetes/Kyma secrets
  (see [`env`](../env) module), or a manually constructed `OAuth2ServiceConfiguration`

## Supported Identity Services & Algorithms

See the [java-security README](../java-security) — this module contains the same
validators, so supported identity services (XSUAA, SAP Identity) and token signature
algorithms are identical.
