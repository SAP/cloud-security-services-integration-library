# Apache HttpClient Migration Guide

## Overview

In version **4.0.1**, the token-client library migrated from **Apache HttpClient 4** to **Java 11 HttpClient** as the default implementation.

**Key Points:**
- Java 11 HttpClient is now the default (no external dependencies required)
- Apache HttpClient 4 constructors are **deprecated** and will be removed in version 5.0.0
- Custom HTTP client implementations (including Apache HttpClient 4 and 5) can be provided via the `HttpRequestExecutor` interface

## Migration Options

### Option 1: Use Default Java HttpClient (Recommended)

**If you're using default constructors**, no code changes needed:

```java
// Automatically uses Java 11 HttpClient
OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService();
OAuth2TokenService tokenService = new DefaultOAuth2TokenService();
OidcConfigurationService oidcService = new DefaultOidcConfigurationService();
```

**If you're using `HttpClientFactory` or `DefaultHttpClientFactory`**, migrate to `SecurityHttpClientProvider`:

**Before (Version 3.x):**
```java
import com.sap.cloud.security.client.HttpClientFactory;

CloseableHttpClient httpClient = HttpClientFactory.create(clientIdentity);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(httpClient);
```

**After (Version 4.0.1):**
```java
import com.sap.cloud.security.client.SecurityHttpClientProvider;

SecurityHttpClient httpClient = SecurityHttpClientProvider.createClient(clientIdentity);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(httpClient);
```

**Benefits:**
- ✅ No external dependencies
- ✅ Built into Java 11+
- ✅ Future-proof API

---

### Option 2: Continue Using Deprecated Apache HttpClient 4 Constructors (Temporary)

For applications that need more time to migrate:

**Using `HttpClientFactory` (Deprecated):**
```java
import com.sap.cloud.security.client.HttpClientFactory;
import org.apache.http.impl.client.CloseableHttpClient;

// HttpClientFactory.create() is deprecated and will be removed in 5.0.0
CloseableHttpClient httpClient = HttpClientFactory.create(clientIdentity);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(httpClient);
```

**Using direct Apache HttpClient constructors (Deprecated):**
```java
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

CloseableHttpClient httpClient = HttpClients.custom()
    .setMaxConnTotal(100)
    .setMaxConnPerRoute(20)
    .build();

// These constructors are deprecated and will be removed in 5.0.0
OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService(httpClient);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(httpClient);
OidcConfigurationService oidcService = new DefaultOidcConfigurationService(httpClient);
```

**Important:**
- ⚠️ **Deprecated in 4.0.1** - Will be removed in 5.0.0
- Apache HttpClient 4 is included as a transitive dependency for backward compatibility

---

### Option 3: Custom HTTP Client Implementation (Recommended for Custom Configurations)

If you need custom HTTP client features (proxy, connection pooling, mTLS), implement the `HttpRequestExecutor` interface.

This approach is **future-proof** and works with any HTTP client library (Apache HttpClient 4, Apache HttpClient 5, etc.).

**Benefits:**
- ✅ Future-proof
- ✅ Works with any HTTP client library (Apache 4, Apache 5, etc.)
- ✅ Full control over HTTP client configuration

**For complete examples with Apache HttpClient 4 and 5, see [CUSTOM_HTTPCLIENT.md](CUSTOM_HTTPCLIENT.md).**

---

## Deprecation Timeline

| Version | Apache HttpClient 4 Support | Recommended Action |
|---------|----------------------------|-------------------|
| **3.x** | ✅ Native support (default) | - |
| **4.x** | ⚠️ Deprecated constructors (transitive dependency) | Migrate to Option 1 or Option 3 |
| **5.0.0** | ❌ Deprecated constructors removed | Must use Option 1 or Option 3 |

---

## Affected Classes

The following constructors are deprecated in version 4.0.1 and will be removed in 5.0.0:

```java
// DefaultOAuth2TokenKeyService
@Deprecated(since = "4.0.1", forRemoval = true)
public DefaultOAuth2TokenKeyService(CloseableHttpClient httpClient)

// DefaultOAuth2TokenService
@Deprecated(since = "4.0.1", forRemoval = true)
public DefaultOAuth2TokenService(CloseableHttpClient httpClient)
public DefaultOAuth2TokenService(CloseableHttpClient httpClient, TokenCacheConfiguration config)

// DefaultOidcConfigurationService
@Deprecated(since = "4.0.1", forRemoval = true)
public DefaultOidcConfigurationService(CloseableHttpClient httpClient)
```

---

## FAQ

**Q: Why was Apache HttpClient 4 removed as the default?**
A: To eliminate external dependencies and modernize the library. Java 11 HttpClient is built into the JDK and covers most use cases.

**Q: Can I still use Apache HttpClient 4 or 5?**
A: Yes! Use Option 2 (deprecated, temporary) or Option 3 (future-proof, recommended).

**Q: Do I need to change my code?**
A: Only if you're currently passing an `CloseableHttpClient` to the constructors. Use the default constructors (Option 1) or implement `HttpRequestExecutor` (Option 3).

**Q: When will deprecated methods be removed?**
A: In version 5.0.0. You have the entire 4.x series to migrate.

---

## Need Help?

- **Custom HTTP client examples:** [CUSTOM_HTTPCLIENT.md](CUSTOM_HTTPCLIENT.md)
- **Migration guide:** [MIGRATION_4.0.md](../MIGRATION_4.0.md)
- **Issues:** https://github.com/SAP/cloud-security-services-integration-library/issues
