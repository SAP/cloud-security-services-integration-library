# Custom HTTP Client Integration

## Overview

Starting with version 4.0.0, the token-client library uses **Java 11's HttpClient** as the default HTTP client implementation. If you need to use a different HTTP client library (Apache HttpClient, OkHttp, etc.), you can provide your own implementation using the simple `HttpRequestExecutor` interface.

## Why Use a Custom HTTP Client?

You might want to use a custom HTTP client if you need:
- Specific proxy configurations
- Custom connection pooling settings
- Corporate SSL certificates or mTLS
- Advanced retry logic
- Request/response logging
- Integration with existing HTTP client infrastructure

## The Simple Approach: HttpRequestExecutor Interface

Instead of maintaining separate adapter modules for each HTTP client library, we provide a simple functional interface that you can implement:

```java
@FunctionalInterface
public interface HttpRequestExecutor {
    HttpResponse execute(URI uri, String method, Map<String, String> headers, byte[] body)
        throws HttpClientException;
}
```

## Examples

### Apache HttpClient 4.x

For Apache HttpClient 4.x, we provide a ready-to-use `HttpRequestExecutor` implementation called `ApacheHttpClient4Executor`.
This is the same implementation the library uses internally for backward compatibility.

**Using the built-in executor (simplest approach):**

```java
import com.sap.cloud.security.client.*;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

// Configure your Apache HttpClient
CloseableHttpClient apacheClient = HttpClients.custom()
    .setMaxConnTotal(100)
    .setMaxConnPerRoute(20)
    .build();

// Use the built-in ApacheHttpClient4Executor
SecurityHttpClient client = new CustomHttpClientAdapter(
    new ApacheHttpClient4Executor(apacheClient),
    apacheClient::close
);

// Use with token services
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client);
```

> **Note:** `ApacheHttpClient4Executor` is deprecated and will be removed in version 5.0.0.
> Consider migrating to Java 11 HttpClient (default) or Apache HttpClient 5.

**Custom executor (for advanced configuration):**

```java
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import com.sap.cloud.security.client.*;

// Configure your Apache HttpClient
CloseableHttpClient apacheClient = HttpClients.custom()
    .setDefaultRequestConfig(RequestConfig.custom()
        .setProxy(new HttpHost("proxy.company.com", 8080))
        .setConnectTimeout(10000)
        .setSocketTimeout(60000)
        .build())
    .setRetryHandler(new DefaultHttpRequestRetryHandler(3, true))
    .build();

// Create executor
HttpRequestExecutor executor = (uri, method, headers, body) -> {
    HttpPost request = new HttpPost(uri);
    headers.forEach(request::addHeader);
    if (body != null) {
        request.setEntity(new ByteArrayEntity(body));
    }

    return apacheClient.execute(request, response -> {
        String responseBody = EntityUtils.toString(response.getEntity());
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

// Wrap in SecurityHttpClient
SecurityHttpClient client = new CustomHttpClientAdapter(executor);

// Use with token services
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client);
```

### Apache HttpClient 5.x

```java
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;

CloseableHttpClient client5 = HttpClients.custom()
    .setDefaultRequestConfig(RequestConfig.custom()
        .setConnectionRequestTimeout(Timeout.ofSeconds(5))
        .setResponseTimeout(Timeout.ofSeconds(30))
        .build())
    .build();

HttpRequestExecutor executor = (uri, method, headers, body) -> {
    ClassicHttpRequest request = new HttpPost(uri);
    headers.forEach(request::addHeader);
    if (body != null) {
        request.setEntity(new ByteArrayEntity(body, ContentType.APPLICATION_FORM_URLENCODED));
    }

    return client5.execute(request, response -> {
        String responseBody = EntityUtils.toString(response.getEntity());
        Map<String, String> responseHeaders = new HashMap<>();
        for (Header header : response.getAllHeaders()) {
            responseHeaders.put(header.getName(), header.getValue());
        }
        return new HttpRequestExecutor.HttpResponse(
            response.getCode(),
            responseHeaders,
            responseBody
        );
    });
};

SecurityHttpClient client = new CustomHttpClientAdapter(executor);
```

### OkHttp

```java
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

OkHttpClient okHttpClient = new OkHttpClient.Builder()
    .connectTimeout(10, TimeUnit.SECONDS)
    .readTimeout(30, TimeUnit.SECONDS)
    .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("proxy.company.com", 8080)))
    .build();

HttpRequestExecutor executor = (uri, method, headers, body) -> {
    Request.Builder builder = new Request.Builder().url(uri.toURL());
    headers.forEach(builder::addHeader);

    RequestBody requestBody = body != null
        ? RequestBody.create(body, okhttp3.MediaType.parse("application/x-www-form-urlencoded"))
        : null;
    builder.method(method, requestBody);

    try (Response response = okHttpClient.newCall(builder.build()).execute()) {
        Map<String, String> responseHeaders = new HashMap<>();
        response.headers().forEach(pair ->
            responseHeaders.put(pair.getFirst(), pair.getSecond()));

        String responseBody = response.body() != null ? response.body().string() : "";

        return new HttpRequestExecutor.HttpResponse(
            response.code(),
            responseHeaders,
            responseBody
        );
    }
};

SecurityHttpClient client = new CustomHttpClientAdapter(executor);
```

### Java 11 HttpClient with Custom Configuration

Even if you want to stick with Java 11's HttpClient but need custom configuration:

```java
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

HttpClient javaClient = HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(10))
    .proxy(ProxySelector.of(new InetSocketAddress("proxy.company.com", 8080)))
    .sslContext(customSSLContext)
    .build();

HttpRequestExecutor executor = (uri, method, headers, body) -> {
    HttpRequest.Builder builder = HttpRequest.newBuilder()
        .uri(uri)
        .timeout(Duration.ofSeconds(30));

    headers.forEach(builder::header);

    if (body != null && body.length > 0) {
        builder.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
    } else {
        builder.method(method, HttpRequest.BodyPublishers.noBody());
    }

    HttpResponse<String> response = javaClient.send(
        builder.build(),
        HttpResponse.BodyHandlers.ofString()
    );

    Map<String, String> responseHeaders = new HashMap<>();
    response.headers().map().forEach((key, values) -> {
        if (!values.isEmpty()) {
            responseHeaders.put(key, values.get(0));
        }
    });

    return new HttpRequestExecutor.HttpResponse(
        response.statusCode(),
        responseHeaders,
        response.body()
    );
};

SecurityHttpClient client = new CustomHttpClientAdapter(executor);
```

## Spring Boot Integration

For Spring Boot applications, you can provide your custom HTTP client as a bean:

```java
@Configuration
public class HttpClientConfig {

    @Bean
    public SecurityHttpClient securityHttpClient() {
        // Your custom HTTP client setup
        CloseableHttpClient apacheClient = HttpClients.custom()
            .setDefaultRequestConfig(...)
            .build();

        HttpRequestExecutor executor = (uri, method, headers, body) -> {
            // Your executor implementation
        };

        return new CustomHttpClientAdapter(executor);
    }
}
```

The autoconfigured token services will automatically use your custom bean.

## Resource Management

If your HTTP client needs cleanup (closing connections, etc.), you can pass a close handler to `CustomHttpClientAdapter`:

```java
CloseableHttpClient apacheClient = HttpClients.createDefault();
HttpRequestExecutor executor = new ApacheHttpClient4Executor(apacheClient);

// Pass close handler as second parameter
SecurityHttpClient client = new CustomHttpClientAdapter(executor, apacheClient::close);

try {
    OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client);
    // Use the service
} finally {
    client.close(); // This will call apacheClient.close()
}
```

Without a close handler, the `close()` method is a no-op and you must manage the lifecycle yourself:

```java
CloseableHttpClient apacheClient = HttpClients.createDefault();
HttpRequestExecutor executor = (uri, method, headers, body) -> { ... };
SecurityHttpClient client = new CustomHttpClientAdapter(executor);

try {
    OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client);
    // Use the service
} finally {
    apacheClient.close(); // Clean up your client manually
}
```

## Migration from Previous Versions

If you were previously using version < 4.0.0:

**Before (< 4.0.0):**
```java
// Apache HttpClient 4.x was the only option
CloseableHttpClient client = HttpClients.createDefault();
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client);
```

**After (4.0.0+ with default):**
```java
// Java 11 HttpClient is now the default - no configuration needed
SecurityHttpClient client = SecurityHttpClientProvider.createClient(null);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client);
```

**After (4.0.0+ with custom executor):**
```java
// Explicit custom configuration for any HTTP client library
CloseableHttpClient apacheClient = HttpClients.custom()...build();
HttpRequestExecutor executor = (uri, method, headers, body) -> { ... };
SecurityHttpClient client = new CustomHttpClientAdapter(executor);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client);
```

**Benefits:**
- ✅ Works with any HTTP client library (4.x, 5.x, OkHttp, etc.)
- ✅ No need for separate adapter modules
- ✅ Full control over HTTP client configuration
- ✅ Future-proof - no breaking changes when HTTP client libraries update

## FAQ

**Q: Should I use the default Java 11 HttpClient or a custom one?**

A: Use the default unless you have specific requirements (proxy, mTLS, custom pooling, etc.). The default is zero-configuration and works for most cases.

**Q: What happened to Apache HttpClient support?**

A: In version 4.0.0, we switched from Apache HttpClient 4.x to Java 11's HttpClient as the default. If you need to use Apache HttpClient (any version) or any other HTTP client library, you can easily integrate it using the `HttpRequestExecutor` interface shown in the examples above.

**Q: Can I still use Apache HttpClient 4.x?**

A: Yes! See the example above. You just need to implement the simple executor interface.

**Q: Does this work with Apache HttpClient 5.x?**

A: Yes! The executor interface is agnostic to the HTTP client library version.

**Q: How do I handle connection pooling?**

A: Configure it in your HTTP client before passing it to the executor. The library doesn't manage pooling - that's up to your HTTP client configuration.

## Special Use Cases

### Using with SAP Cloud SDK's HttpClientAccessor

If you're using SAP Cloud SDK and want to leverage its `HttpClientAccessor` for destination management, you can integrate it like this:

**Version 4.0.0+ with HttpClientAccessor:**
```java
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpClientAccessor;
import com.sap.cloud.security.client.*;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

// Get HttpClient from Cloud SDK's HttpClientAccessor
CloseableHttpClient apacheClient = (CloseableHttpClient) HttpClientAccessor.getHttpClient(destination);

// Create executor that wraps the Cloud SDK's HttpClient
HttpRequestExecutor executor = (uri, method, headers, body) -> {
    HttpPost request = new HttpPost(uri);

    // Add headers
    headers.forEach(request::addHeader);

    // Add body if present
    if (body != null) {
        request.setEntity(new ByteArrayEntity(body));
    }

    // Execute with Cloud SDK's HttpClient
    try (CloseableHttpResponse response = apacheClient.execute(request)) {
        String responseBody = EntityUtils.toString(response.getEntity());

        Map<String, String> responseHeaders = new HashMap<>();
        for (org.apache.http.Header header : response.getAllHeaders()) {
            responseHeaders.put(header.getName(), header.getValue());
        }

        return new HttpRequestExecutor.HttpResponse(
            response.getStatusLine().getStatusCode(),
            responseHeaders,
            responseBody
        );
    }
};

// Wrap in SecurityHttpClient
SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor);

// Create token service with your custom client
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(
    securityClient,
    TokenCacheConfiguration.defaultConfiguration()
);
```

**Migration from 3.x:**
```java
// Before (Version < 4.0.0):
CloseableHttpClient client = (CloseableHttpClient) HttpClientAccessor.getHttpClient(destination);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client, tokenCacheConfiguration);

// After (Version 4.0.0+):
CloseableHttpClient client = (CloseableHttpClient) HttpClientAccessor.getHttpClient(destination);
HttpRequestExecutor executor = (uri, method, headers, body) -> { /* implementation above */ };
SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityClient, tokenCacheConfiguration);
```

**Benefits of this approach:**
- ✅ Leverages Cloud SDK's destination management
- ✅ Inherits proxy, authentication, and connection pooling from destination configuration
- ✅ Compatible with both on-premise and cloud destinations
- ✅ Maintains full Cloud SDK feature compatibility