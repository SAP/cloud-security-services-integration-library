# XSUAA JWKS trust anchor: design and test migration

## Security invariant

The XSUAA signature validator must obtain verification keys only from the endpoint
derived from the application's service configuration. Neither a token's `jku` header
nor an automatically discovered `XsuaaJkuFactory` may select the verification-key
endpoint, even when a test-support artifact is accidentally present at runtime.

## Implementation plan

1. Remove `XsuaaJkuFactory` discovery and invocation from `XsuaaJwtSignatureValidator`.
   Keep the configured `uaadomain` endpoint, legacy service URL handling, tenant
   parameter and configured `verificationkey` fallback unchanged.
2. Stop registering `XsuaaLocalhostJkuFactory` in the test artifact's main resources.
   Retain the internal interface and helper class as deprecated types for binary
   compatibility; they no longer affect production XSUAA validation.
3. Restrict the retained localhost helpers to parsed HTTP(S) URLs with an exact
   localhost/loopback host and no user information. Harden the companion IAS
   localhost-issuer helper without removing its explicitly localhost-scoped
   compatibility behavior.
4. Add regression tests with independently generated trusted and attacker RSA keys.
   Test the default production chain with the test library present and verify that
   only the configured JWKS endpoint is requested. Also test an independently
   registered legacy provider, so removing just the shipped service descriptor
   cannot accidentally become the only protection.
5. Run the reactor tests and the servlet/Spring sample tests. Verify the packaged
   service registrations and document the migration of older localhost fixtures.

## Compatibility and migration

Normal production service bindings do not require changes. XSUAA continues to use
the configured key endpoint; the original token `jku` is ignored. A correctly signed
token is not rejected merely because its unused `jku` header differs.

Older tests that used `uaadomain=localhost` or `http://localhost` while relying on
the token header to supply a random port must now configure the actual mock-server
base URL, including its scheme and port:

```java
OAuth2ServiceConfiguration config = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
        .withClientId(clientId)
        .withUrl(mockServer.baseUrl())
        .withProperty(ServiceConstants.XSUAA.UAA_DOMAIN, mockServer.baseUrl())
        .build();
```

`SecurityTestContext.getOAuth2ServiceConfigurationBuilderFromFile(...)` already sets
the mock-server URL and XSUAA `uaadomain` appropriately. Spring tests should likewise
use the actual mock base URL in their service properties. No new opt-in flag restores
token-controlled JWKS selection.

`java-security-test` must still be declared with `<scope>test</scope>` and excluded
from production packaging. This fix does not make test-support dependencies suitable
for a production runtime.

## Scope

This change addresses the XSUAA test-provider trust-anchor switch and the retained
localhost helpers. It does not change audience/broker-clone semantics, IAS tenant
validation, proof-of-possession defaults, or the configured static-key fallback.
