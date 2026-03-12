# Apache HttpClient 4 Migration Guide

## Overview

In version **3.x**, the token-client library used **Apache HttpClient 4** as the default HTTP client. Starting with version **4.0.0**, the library has migrated to **Java 11's HttpClient** as the default implementation to eliminate external dependencies and modernize the codebase.

This guide explains:
1. The migration path away from Apache HttpClient 4
2. How to use the backward compatibility constructors (deprecated)
3. How to migrate to the new approach with minimal effort
4. How to implement a custom HTTP client executor if needed

## Quick Summary

| Version | Default HTTP Client | Apache HttpClient 4 Support |
|---------|---------------------|----------------------------|
| 3.x | Apache HttpClient 4 (built-in) | ✅ Native support |
| 4.0.0+ | Java 11 HttpClient (built-in) | ⚠️ Deprecated backward compatibility |
| 5.0.0 (planned) | Java 11 HttpClient (built-in) | ❌ Removed |

## Migration Paths

### Path 1: Use Default Java HttpClient (Recommended)

**Best for:** Most applications that don't need custom HTTP client configuration.

**Before (Version 3.x):**
```java
// In version 3.x, Apache HttpClient 4 was used internally
OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService();
OAuth2TokenService tokenService = new DefaultOAuth2TokenService();
OidcConfigurationService oidcService = new DefaultOidcConfigurationService();
```

**After (Version 4.0.0+):**
```java
// In version 4.0.0+, Java 11 HttpClient is used internally - no code changes needed!
OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService();
OAuth2TokenService tokenService = new DefaultOAuth2TokenService();
OidcConfigurationService oidcService = new DefaultOidcConfigurationService();
```

**Migration steps:**
1. Update to version 4.0.0+
2. Remove Apache HttpClient 4 dependencies from your `pom.xml` (if not used elsewhere)
3. No code changes required!

**Benefits:**
- ✅ Zero code changes
- ✅ No external dependencies
- ✅ Built into Java 11+
- ✅ Modern, performant HTTP client

---

### Path 2: Backward Compatibility (Deprecated)

**Best for:** Applications that need more time to migrate and want to keep using Apache HttpClient 4 temporarily.

**Before (Version 3.x):**
```java
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

CloseableHttpClient httpClient = HttpClients.custom()
    .setMaxConnTotal(100)
    .setMaxConnPerRoute(20)
    .build();

OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService(httpClient);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(httpClient);
OidcConfigurationService oidcService = new DefaultOidcConfigurationService(httpClient);
```

**After (Version 4.0.0 - Deprecated):**
```java
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

// Your existing code continues to work!
CloseableHttpClient httpClient = HttpClients.custom()
    .setMaxConnTotal(100)
    .setMaxConnPerRoute(20)
    .build();

// These constructors are deprecated but still functional
OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService(httpClient);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(httpClient);
OidcConfigurationService oidcService = new DefaultOidcConfigurationService(httpClient);
```

**Migration steps:**
1. Update to version 4.0.0+
2. Keep your existing code - it still works!
3. Ensure Apache HttpClient 4 dependency is in your `pom.xml`:
   ```xml
   <dependency>
       <groupId>org.apache.httpcomponents</groupId>
       <artifactId>httpclient</artifactId>
       <version>4.5.14</version>
   </dependency>
   ```
4. You'll see deprecation warnings - these are reminders to migrate before version 5.0.0

**Important Notes:**
- ⚠️ **Deprecated in 4.0.0** - These constructors are marked for removal
- ⚠️ **Will be removed in 5.0.0** - Plan to migrate before then
- ⚠️ You must explicitly add Apache HttpClient 4 to your dependencies
- ℹ️ The library internally uses `ApacheHttpClient4Adapter` (also deprecated)

---

### Path 3: Custom HttpClient with Adapter (Migration Path)

**Best for:** Applications that need custom HTTP client configuration and want to migrate away from deprecated constructors.

**Option 3a: Use the ApacheHttpClient4Adapter directly (Deprecated)**

```java
import com.sap.cloud.security.client.ApacheHttpClient4Adapter;
import com.sap.cloud.security.client.SecurityHttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

CloseableHttpClient apacheClient = HttpClients.custom()
    .setMaxConnTotal(100)
    .setMaxConnPerRoute(20)
    .build();

// Wrap Apache HttpClient 4 with the adapter
SecurityHttpClient securityClient = new ApacheHttpClient4Adapter(apacheClient);

// Use with token services
OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService(securityClient);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityClient);
OidcConfigurationService oidcService = new DefaultOidcConfigurationService(securityClient);
```

**Notes:**
- ⚠️ `ApacheHttpClient4Adapter` is also deprecated and will be removed in version 5.0.0
- This is a stepping stone toward Path 4 (Custom Executor)

**Option 3b: Migrate to Apache HttpClient 5 (Not Deprecated)**

If you need Apache HttpClient features, migrate to version 5:

```java
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import com.sap.cloud.security.client.CustomHttpClientAdapter;
import com.sap.cloud.security.client.HttpRequestExecutor;

CloseableHttpClient client5 = HttpClients.custom()
    .setMaxConnTotal(100)
    .setMaxConnPerRoute(20)
    .build();

// Create executor with HttpClient 5
HttpRequestExecutor executor = (uri, method, headers, body) -> {
    // Implementation for Apache HttpClient 5
    // See CUSTOM_HTTP_CLIENT.md for full example
};

SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor);

// Use with token services
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityClient);
```

---

### Path 4: Custom HttpRequestExecutor (Future-Proof)

**Best for:** Applications that need custom HTTP client features and want a future-proof solution.

This approach works with **any** HTTP client library (Apache 4, Apache 5, OkHttp, etc.) and is **not deprecated**.

**Step 1: Implement HttpRequestExecutor**

```java
import com.sap.cloud.security.client.HttpRequestExecutor;
import org.apache.http.client.methods.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

CloseableHttpClient apacheClient = HttpClients.custom()
    .setMaxConnTotal(100)
    .setMaxConnPerRoute(20)
    .setDefaultRequestConfig(RequestConfig.custom()
        .setConnectTimeout(10000)
        .setSocketTimeout(30000)
        .build())
    .build();

HttpRequestExecutor executor = (uri, method, headers, body) -> {
    // Create appropriate request based on HTTP method
    HttpUriRequest request;
    switch (method.toUpperCase()) {
        case "GET":
            request = new HttpGet(uri);
            break;
        case "POST":
            HttpPost post = new HttpPost(uri);
            if (body != null) {
                post.setEntity(new ByteArrayEntity(body));
            }
            request = post;
            break;
        // Add other methods as needed
        default:
            throw new IllegalArgumentException("Unsupported method: " + method);
    }

    // Add headers
    headers.forEach(request::addHeader);

    // Execute request
    return apacheClient.execute(request, response -> {
        String responseBody = response.getEntity() != null
            ? EntityUtils.toString(response.getEntity())
            : "";

        Map<String, String> responseHeaders = new HashMap<>();
        for (Header header : response.getAllHeaders()) {
            responseHeaders.put(header.getName(), header.getValue());
        }

        return new HttpRequestExecutor.HttpResponse(
            response.getStatusLine().getStatusCode(),
            responseHeaders,
            responseBody
        );
    });
};
```

**Step 2: Wrap in CustomHttpClientAdapter**

```java
import com.sap.cloud.security.client.CustomHttpClientAdapter;
import com.sap.cloud.security.client.SecurityHttpClient;

SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor);
```

**Step 3: Use with Token Services**

```java
OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService(securityClient);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityClient);
OidcConfigurationService oidcService = new DefaultOidcConfigurationService(securityClient);
```

**Benefits:**
- ✅ Future-proof - Not deprecated
- ✅ Works with any HTTP client library
- ✅ Full control over HTTP client configuration
- ✅ Easy to test and mock

**Full examples:**
See [CUSTOM_HTTP_CLIENT.md](CUSTOM_HTTP_CLIENT.md) for complete examples with Apache HttpClient 4, Apache HttpClient 5, and OkHttp.

---

## Comparison Table

| Approach | Code Changes | Dependencies | Deprecated | Future-Proof |
|----------|--------------|--------------|------------|--------------|
| Path 1: Default Java HttpClient | None | None (built-in) | ❌ No | ✅ Yes |
| Path 2: Deprecated Constructors | None | Apache HttpClient 4 | ⚠️ Yes (4.0.0) | ❌ Removed in 5.0.0 |
| Path 3a: ApacheHttpClient4Adapter | Minimal | Apache HttpClient 4 | ⚠️ Yes (4.0.0) | ❌ Removed in 5.0.0 |
| Path 3b: Apache HttpClient 5 | Moderate | Apache HttpClient 5 | ❌ No | ✅ Yes |
| Path 4: Custom Executor | Moderate | Any HTTP client | ❌ No | ✅ Yes |

---

## Deprecation Timeline

| Version | Status |
|---------|--------|
| **3.x** | Apache HttpClient 4 constructors are the standard way |
| **4.0.0** | Apache HttpClient 4 constructors deprecated, `ApacheHttpClient4Adapter` added as deprecated |
| **4.x** | Deprecation warnings encourage migration to new approaches |
| **5.0.0** | Apache HttpClient 4 constructors and `ApacheHttpClient4Adapter` will be **removed** |

**Recommendation:** Migrate to **Path 1** (default Java HttpClient) or **Path 4** (custom executor) before version 5.0.0.

---

## Affected Classes and Methods

The following constructors are deprecated in version 4.0.0:

### DefaultOAuth2TokenKeyService
```java
@Deprecated(since = "4.0.0", forRemoval = true)
public DefaultOAuth2TokenKeyService(org.apache.http.impl.client.CloseableHttpClient httpClient)
```

### DefaultOAuth2TokenService
```java
@Deprecated(since = "4.0.0", forRemoval = true)
public DefaultOAuth2TokenService(org.apache.http.impl.client.CloseableHttpClient httpClient)

@Deprecated(since = "4.0.0", forRemoval = true)
public DefaultOAuth2TokenService(
    org.apache.http.impl.client.CloseableHttpClient httpClient,
    TokenCacheConfiguration tokenCacheConfiguration)
```

### DefaultOidcConfigurationService
```java
@Deprecated(since = "4.0.0", forRemoval = true)
public DefaultOidcConfigurationService(org.apache.http.impl.client.CloseableHttpClient httpClient)
```

### ApacheHttpClient4Adapter
```java
@Deprecated(since = "4.0.0", forRemoval = true)
public class ApacheHttpClient4Adapter implements SecurityHttpClient
```

---

## FAQ

### Q: Why was Apache HttpClient 4 removed as the default?
**A:** To eliminate external dependencies and modernize the library. Java 11's HttpClient is built into the JDK, performs well, and covers most use cases.

### Q: Can I still use Apache HttpClient 4?
**A:** Yes, temporarily. Use the deprecated constructors (Path 2) or the deprecated adapter (Path 3a). However, these will be removed in version 5.0.0.

### Q: What if I need custom HTTP client features?
**A:** Implement the `HttpRequestExecutor` interface (Path 4). This works with any HTTP client library and is future-proof.

### Q: Do I need to change my code if I'm using the default constructor?
**A:** No! The default constructors (no parameters) automatically use Java 11's HttpClient.

### Q: When will the deprecated methods be removed?
**A:** In version 5.0.0. You have the entire 4.x version series to migrate.

### Q: Is Apache HttpClient 5 supported?
**A:** Yes! Use Path 3b or Path 4. Apache HttpClient 5 support is not deprecated.

### Q: What if I can't migrate before version 5.0.0?
**A:** Stay on version 4.x until you can migrate. However, you won't receive new features or bug fixes after 5.0.0 is released.

---

## Need Help?

- **Custom HTTP client examples:** See [CUSTOM_HTTP_CLIENT.md](CUSTOM_HTTP_CLIENT.md)
- **General migration guide:** See [MIGRATION_4.0.md](../MIGRATION_4.0.md)
- **Issues:** https://github.com/SAP/cloud-security-xsuaa-integration/issues
