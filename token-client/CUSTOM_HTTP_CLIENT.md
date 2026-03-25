# Custom HTTP Client Integration

## Overview

The token-client library uses **Java 11 HttpClient** as the default. If you need custom HTTP client features (proxy, connection pooling, mTLS, etc.), you can provide your own implementation using the `HttpRequestExecutor` interface.

## When to Use Custom HTTP Client

Use a custom HTTP client if you need:
- Specific proxy configurations
- Custom connection pooling settings
- Corporate SSL certificates or mTLS
- Advanced retry logic
- Request/response logging
- Integration with existing HTTP client infrastructure

## The HttpRequestExecutor Interface

```java
@FunctionalInterface
public interface HttpRequestExecutor {
    HttpResponse execute(URI uri, String method, Map<String, String> headers, byte[] body)
        throws HttpClientException;
}
```

## Examples

### Apache HttpClient 5

```java
import com.sap.cloud.security.client.*;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;

// 1. Configure your HTTP client
CloseableHttpClient client5 = HttpClients.custom()
    .setDefaultRequestConfig(RequestConfig.custom()
        .setConnectionRequestTimeout(Timeout.ofSeconds(5))
        .setResponseTimeout(Timeout.ofSeconds(30))
        .build())
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

### OkHttp

```java
import com.sap.cloud.security.client.*;
import okhttp3.*;

// 1. Configure OkHttp
OkHttpClient okHttpClient = new OkHttpClient.Builder()
    .connectTimeout(10, TimeUnit.SECONDS)
    .readTimeout(30, TimeUnit.SECONDS)
    .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("proxy.company.com", 8080)))
    .build();

// 2. Implement HttpRequestExecutor
HttpRequestExecutor executor = (uri, method, headers, body) -> {
    Request.Builder builder = new Request.Builder().url(uri.toURL());
    headers.forEach(builder::addHeader);

    RequestBody requestBody = body != null
        ? RequestBody.create(body, MediaType.parse("application/x-www-form-urlencoded"))
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

// 3. Wrap in SecurityHttpClient
SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor);

// 4. Use with token services
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityClient);
```

### Java 11 HttpClient with Custom Configuration

```java
import com.sap.cloud.security.client.*;
import java.net.http.*;
import java.time.Duration;

// 1. Configure Java HttpClient
HttpClient javaClient = HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(10))
    .proxy(ProxySelector.of(new InetSocketAddress("proxy.company.com", 8080)))
    .sslContext(customSSLContext)
    .build();

// 2. Implement HttpRequestExecutor
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

// 3. Wrap in SecurityHttpClient
SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor);

// 4. Use with token services
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityClient);
```

## Spring Boot Integration

Provide your custom HTTP client as a Spring bean:

```java
@Configuration
public class HttpClientConfig {

    @Bean
    public SecurityHttpClient securityHttpClient() {
        // Configure your HTTP client
        CloseableHttpClient client5 = HttpClients.custom()
            .setDefaultRequestConfig(...)
            .build();

        // Implement executor
        HttpRequestExecutor executor = (uri, method, headers, body) -> {
            // Your implementation
        };

        return new CustomHttpClientAdapter(executor, client5::close);
    }
}
```

The autoconfigured token services will automatically use your custom bean.

## Resource Management

If your HTTP client needs cleanup, pass a close handler to `CustomHttpClientAdapter`:

```java
CloseableHttpClient client = HttpClients.createDefault();
HttpRequestExecutor executor = /* your implementation */;

// Pass close handler as second parameter
SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor, client::close);

try {
    OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityClient);
    // Use the service
} finally {
    securityClient.close(); // Calls client.close()
}
```

Without a close handler, `close()` is a no-op and you must manage lifecycle yourself.

## Apache HttpClient 4 Support

> **Deprecated:** Apache HttpClient 4 support via deprecated constructors will be removed in version 5.0.0.

Apache HttpClient 4 can still be used via custom `HttpRequestExecutor` implementation:

```java
import com.sap.cloud.security.client.*;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

CloseableHttpClient apacheClient = HttpClients.custom()
    .setDefaultRequestConfig(RequestConfig.custom()
        .setConnectTimeout(10000)
        .setSocketTimeout(30000)
        .build())
    .build();

HttpRequestExecutor executor = (uri, method, headers, body) -> {
    HttpPost request = new HttpPost(uri);
    headers.forEach(request::addHeader);
    if (body != null) {
        request.setEntity(new ByteArrayEntity(body));
    }

    return apacheClient.execute(request, response -> {
        String responseBody = EntityUtils.toString(response.getEntity());
        Map<String, String> responseHeaders = new HashMap<>();
        for (var header : response.getAllHeaders()) {
            responseHeaders.put(header.getName(), header.getValue());
        }
        return new HttpRequestExecutor.HttpResponse(
            response.getStatusLine().getStatusCode(),
            responseHeaders,
            responseBody
        );
    });
};

SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor, apacheClient::close);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityClient);
```

## FAQ

**Q: Should I use the default Java 11 HttpClient or a custom one?**

A: Use the default unless you have specific requirements (proxy, mTLS, custom pooling). The default is zero-configuration and works for most cases.

**Q: What happened to native Apache HttpClient support?**

A: In version 4.0.0, we switched to Java 11 HttpClient as the default. Apache HttpClient (any version) can be used via the `HttpRequestExecutor` interface shown above.

**Q: Does this work with Apache HttpClient 4 and 5?**

A: Yes! The executor interface works with any HTTP client library.

**Q: How do I handle connection pooling?**

A: Configure it in your HTTP client before passing it to the executor. The library doesn't manage pooling - that's up to your HTTP client configuration.

## See Also

- [APACHE_HTTPCLIENT_MIGRATION.md](APACHE_HTTPCLIENT_MIGRATION.md) - Migration guide from Apache HttpClient 4
- [MIGRATION_4.0.md](../MIGRATION_4.0.md) - General migration guide
- [token-client README](README.md) - Token client documentation
