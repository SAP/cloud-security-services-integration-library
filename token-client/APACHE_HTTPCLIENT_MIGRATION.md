# Apache HttpClient Migration Guide

## Overview

In version **4.0.0**, the token-client library migrated from **Apache HttpClient 4** to **Java 11 HttpClient** as the default implementation.

**Key Points:**
- Java 11 HttpClient is now the default (no external dependencies required)
- Apache HttpClient 4 constructors are **deprecated** and will be removed in version 5.0.0
- Custom HTTP client implementations (including Apache HttpClient 4 and 5) can be provided via the `HttpRequestExecutor` interface

## Migration Options

### Option 1: Use Default Java HttpClient (Recommended)

No code changes needed! The token-client automatically uses Java 11 HttpClient:

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client</artifactId>
    <version>4.0.0</version>
</dependency>
```

```java
// Automatically uses Java 11 HttpClient
OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService();
OAuth2TokenService tokenService = new DefaultOAuth2TokenService();
OidcConfigurationService oidcService = new DefaultOidcConfigurationService();
```

**Benefits:**
- ✅ Zero code changes
- ✅ No external dependencies
- ✅ Built into Java 11+

---

### Option 2: Continue Using Deprecated Apache HttpClient 4 Constructors (Temporary)

For applications that need more time to migrate:

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
- ⚠️ **Deprecated in 4.0.0** - Will be removed in 5.0.0
- Apache HttpClient 4 is included as a transitive dependency for backward compatibility

---

### Option 3: Custom HTTP Client Implementation (Future-Proof)

If you need custom HTTP client features (proxy, connection pooling, mTLS), implement the `HttpRequestExecutor` interface.

This approach works with **any** HTTP client library (Apache HttpClient 4, Apache HttpClient 5, OkHttp, etc.) and is **not deprecated**.

**Example with Apache HttpClient 5:**

```java
import com.sap.cloud.security.client.*;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;

// 1. Configure your HTTP client
CloseableHttpClient client5 = HttpClients.custom()
    .setDefaultRequestConfig(...)
    .build();

// 2. Implement HttpRequestExecutor
HttpRequestExecutor executor = (uri, method, headers, body) -> {
    HttpPost request = new HttpPost(uri);
    headers.forEach(request::addHeader);
    if (body != null) {
        request.setEntity(new ByteArrayEntity(body, ContentType.APPLICATION_FORM_URLENCODED));
    }

    return client5.execute(request, response -> {
        String responseBody = EntityUtils.toString(response.getEntity());
        Map<String, String> responseHeaders = new HashMap<>();
        for (var header : response.getAllHeaders()) {
            responseHeaders.put(header.getName(), header.getValue());
        }
        return new HttpRequestExecutor.HttpResponse(
            response.getCode(),
            responseHeaders,
            responseBody
        );
    });
};

// 3. Wrap in SecurityHttpClient
SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor, client5::close);

// 4. Use with token services
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityClient);
```

**Benefits:**
- ✅ Future-proof - Not deprecated
- ✅ Works with any HTTP client library (Apache 4, Apache 5, OkHttp, etc.)
- ✅ Full control over HTTP client configuration

For complete examples, see [CUSTOM_HTTP_CLIENT.md](CUSTOM_HTTP_CLIENT.md).

---

## Deprecation Timeline

| Version | Apache HttpClient 4 Support | Recommended Action |
|---------|----------------------------|-------------------|
| **3.x** | ✅ Native support (default) | - |
| **4.x** | ⚠️ Deprecated constructors (transitive dependency) | Migrate to Option 1 or Option 3 |
| **5.0.0** | ❌ Deprecated constructors removed | Must use Option 1 or Option 3 |

---

## Affected Classes

The following constructors are deprecated in version 4.0.0 and will be removed in 5.0.0:

```java
// DefaultOAuth2TokenKeyService
@Deprecated(since = "4.0.0", forRemoval = true)
public DefaultOAuth2TokenKeyService(CloseableHttpClient httpClient)

// DefaultOAuth2TokenService
@Deprecated(since = "4.0.0", forRemoval = true)
public DefaultOAuth2TokenService(CloseableHttpClient httpClient)
public DefaultOAuth2TokenService(CloseableHttpClient httpClient, TokenCacheConfiguration config)

// DefaultOidcConfigurationService
@Deprecated(since = "4.0.0", forRemoval = true)
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

- **Custom HTTP client examples:** [CUSTOM_HTTP_CLIENT.md](CUSTOM_HTTP_CLIENT.md)
- **Migration guide:** [MIGRATION_4.0.md](../MIGRATION_4.0.md)
- **Issues:** https://github.com/SAP/cloud-security-services-integration-library/issues
