# Migration Guide: Version 3.x to 4.0.0

This guide helps you migrate your application from version 3.x to 4.0.0 of the SAP BTP Security Services Integration Library.

## Overview

Version 4.0.0 is a major release that upgrades to Spring Boot 4.x and Jakarta EE 10. We provide two migration paths:

1. **Recommended**: Upgrade to Spring Boot 4.x
2. **Alternative**: Stay on Spring Boot 3.x using our legacy compatibility modules

## Table of Contents

1. [Breaking Changes Summary](#breaking-changes-summary)
2. [Migration Path 1: Upgrade to Spring Boot 4.x](#migration-path-1-upgrade-to-spring-boot-4x-recommended)
3. [Migration Path 2: Stay on Spring Boot 3.x](#migration-path-2-stay-on-spring-boot-3x)
4. [Removed Modules](#removed-modules)
5. [Token Client HTTP Client Changes](#token-client-http-client-changes)
6. [Troubleshooting](#troubleshooting)

## Breaking Changes Summary

### Version Updates

| Component | Version 3.x | Version 4.0.0 |
|---|---|---|
| Spring Boot | 3.x | 4.0.3 |
| Spring Framework | 6.x | 7.0.5 |
| Spring Security | 6.x | 7.0.3 |
| Jakarta Servlet API | 6.0.0 | 6.1.0 |

### Removed Modules

The following modules have been removed:

- `spring-xsuaa` → migrate to `spring-security` or `spring-security-legacy`
- `spring-xsuaa-test` → migrate to `java-security-test`
- `spring-xsuaa-it` → migrate to `java-security-test` + `spring-security`
- `spring-security-compatibility` → migrate to `spring-security-legacy`
- Apache HttpClient in token-client → migrate to Java 11 HttpClient (default) or custom implementation

### HTTP Client Changes

- Token-client now uses Java 11 HttpClient by default (no external dependencies)
- Apache HttpClient support available via custom integration (see [CUSTOM_HTTP_CLIENT.md](token-client/CUSTOM_HTTP_CLIENT.md))

## Migration Path 1: Upgrade to Spring Boot 4.x (Recommended)

### Prerequisites

- Java 17 or later
- Spring Boot 4.0.0 or later
- Spring Security 7.0.0 or later

### Step 1: Update Spring Boot Parent

```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>4.0.3</version>
    <relativePath/>
</parent>
```

### Step 2: Update Security Library Dependency

```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>resourceserver-security-spring-boot-starter</artifactId>
    <version>4.0.0</version>
</dependency>
```

### Step 3: Update Jakarta Dependencies

Jakarta Servlet API has been upgraded:

```xml
<dependency>
    <groupId>jakarta.servlet</groupId>
    <artifactId>jakarta.servlet-api</artifactId>
    <version>6.1.0</version>
    <scope>provided</scope>
</dependency>
```

### Step 4: Test Your Application

Run your tests to ensure everything works:

```bash
mvn clean test
```

## Migration Path 2: Stay on Spring Boot 3.x

If you cannot immediately upgrade to Spring Boot 4.x, use the legacy compatibility modules.

### Step 1: Keep Spring Boot 3.x Parent

```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.5.9</version>
    <relativePath/>
</parent>
```

### Step 2: Use Legacy Starter

Replace the standard starter with the legacy starter:

**Before (3.x):**
```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>resourceserver-security-spring-boot-starter</artifactId>
    <version>3.6.8</version>
</dependency>
```

**After (4.0.0 with Spring Boot 3.x compatibility):**
```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>resourceserver-security-spring-boot-starter-legacy</artifactId>
    <version>4.0.0</version>
</dependency>
```

### Step 3: Verify Compatibility

The legacy starter provides:
- Spring Boot 3.5.9 compatibility
- Spring Framework 6.2.15 compatibility
- Spring Security 6.5.7 compatibility
- **Same API** as the main starter

Your application code **does not need to change** - only the dependency in your POM.

### Step 4: Test Your Application

```bash
mvn clean test
```

### When to Upgrade to Spring Boot 4.x

The legacy modules are intended as a **temporary migration path**. Plan to upgrade to Spring Boot 4.x within your next major release cycle.

## Removed Modules

### spring-xsuaa → spring-security / spring-security-legacy

The `spring-xsuaa` module has been removed. Migrate to either:

**For Spring Boot 4.x:**
- Module: `spring-security`
- Starter: `resourceserver-security-spring-boot-starter`
- [Migration Guide](spring-security/Migration_SpringXsuaaProjects.md)

**For Spring Boot 3.x:**
- Module: `spring-security-legacy`
- Starter: `resourceserver-security-spring-boot-starter-legacy`
- [Migration Guide](spring-security-legacy/Migration_SpringXsuaaProjects.md)

### spring-xsuaa-test → java-security-test

**Before:**
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>spring-xsuaa-test</artifactId>
    <version>3.6.8</version>
    <scope>test</scope>
</dependency>
```

**After:**
```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-security-test</artifactId>
    <version>4.0.0</version>
    <scope>test</scope>
</dependency>
```

The `JwtGenerator` class is now in `com.sap.cloud.security.test` package:

```java
// Before
import com.sap.cloud.security.xsuaa.test.JwtGenerator;

// After
import com.sap.cloud.security.test.JwtGenerator;
```

### spring-security-compatibility → spring-security-legacy

**Before:**
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>spring-security-compatibility</artifactId>
    <version>3.6.8</version>
</dependency>
```

**After (Spring Boot 3.x only):**
```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>spring-security-legacy</artifactId>
    <version>4.0.0</version>
</dependency>
```

**Note:** For Spring Boot 4.x, use `spring-security` module directly.

### Token Client: Apache HttpClient → Java 11 HttpClient

The token-client module now uses Java 11 HttpClient as the default. Apache HttpClient 4 is still included as a transitive dependency for backward compatibility.

**Option 1: Use default Java 11 HttpClient (Recommended)**

The `token-client` module now uses Java 11 HttpClient by default - no additional dependencies or code changes required.

**Before (Version 3.x with Apache HttpClient):**
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client</artifactId>
    <version>3.6.8</version>
</dependency>
```

**After (Version 4.0.0 with Java HttpClient):**
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client</artifactId>
    <version>4.0.0</version>
</dependency>
```

No code changes required - the HTTP client change is transparent.

**Option 2: Continue using deprecated Apache HttpClient constructors**

If you have existing code using Apache HttpClient 4, it will continue to work:

```java
// This code still works in 4.x (deprecated, will be removed in 5.0.0)
CloseableHttpClient httpClient = HttpClientFactory.create(clientIdentity);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(httpClient);
```

Apache HttpClient 4 is included transitively - no additional dependency needed.

**Option 3: Provide custom Apache HttpClient 5**

If you need Apache HttpClient 5 for specific features (e.g., connection pooling, proxy support):

1. Add Apache HttpClient 5 dependency:
```xml
<dependency>
    <groupId>org.apache.httpcomponents.client5</groupId>
    <artifactId>httpclient5</artifactId>
    <version>5.6</version>
</dependency>
```

2. Implement `SecurityHttpClientFactory` - see [CUSTOM_HTTP_CLIENT.md](token-client/CUSTOM_HTTP_CLIENT.md) for examples

## Token Client HTTP Client Changes

### Default HTTP Client

Version 4.0.0 uses Java 11 HttpClient by default. No external dependencies required.

**What Changed:**
- **Version 3.x**: Used Apache HttpClient 4.x internally
- **Version 4.0.0**: Uses Java 11 HttpClient (built into JDK)

**Migration:** No code changes needed! The HTTP client is an internal implementation detail.

### Timeout and Connection Pooling

The timeout settings (5s connect, 30s socket) have been preserved. Connection pooling behavior differs slightly - see the [token-client README](token-client/README.md#connection-pooling) for details and configuration options.

### Custom HTTP Client Integration

To use a different HTTP client (Apache HttpClient 4.x/5.x, OkHttp):

1. Implement the `HttpRequestExecutor` interface
2. Register via `SecurityHttpClientFactory` service loader

See comprehensive guide: [CUSTOM_HTTP_CLIENT.md](token-client/CUSTOM_HTTP_CLIENT.md)

Example for Apache HttpClient 5:

```java
public class ApacheHttpClient5Factory implements SecurityHttpClientFactory {
    @Override
    public SecurityHttpClient create() {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        return new ApacheHttpClient5Adapter(httpClient);
    }
}
```

Register in `META-INF/services/com.sap.cloud.security.client.SecurityHttpClientFactory`:
```
com.example.ApacheHttpClient5Factory
```

## Troubleshooting

### NoSuchMethodError or NoClassDefFoundError

**Symptom:** `NoSuchMethodError: org.springframework.boot.http.client.HttpClientSettings.defaults()`

**Cause:** Mixing Spring Boot 4.x and Spring Boot 3.x dependencies

**Solution:** Ensure all Spring Boot dependencies match your chosen version:
- For Spring Boot 4.x: Use `resourceserver-security-spring-boot-starter`
- For Spring Boot 3.x: Use `resourceserver-security-spring-boot-starter-legacy`

### Test Failures After Migration

**Symptom:** Tests fail with context loading errors

**Solution:**
1. Clear Maven cache: `mvn clean`
2. Rebuild: `mvn install -DskipTests`
3. Run tests: `mvn test`

### AutoConfiguration Not Working

**Symptom:** Security beans not auto-configured

**Solution:** Ensure you're using the correct starter:
- Spring Boot 4.x: `resourceserver-security-spring-boot-starter`
- Spring Boot 3.x: `resourceserver-security-spring-boot-starter-legacy`

### Custom HTTP Client Not Used

**Symptom:** Token client still uses default Java HttpClient

**Solution:**
1. Verify `SecurityHttpClientFactory` implementation is in classpath
2. Check `META-INF/services/com.sap.cloud.security.client.SecurityHttpClientFactory` registration
3. Enable debug logging: `logging.level.com.sap.cloud.security=DEBUG`

## Getting Help

- [GitHub Issues](https://github.com/SAP/cloud-security-services-integration-library/issues)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/sap-cloud-platform) (tag: `sap-cloud-platform`)
- [SAP Community](https://community.sap.com/)

## See Also

- [CHANGELOG.md](CHANGELOG.md) - Complete list of changes
- [spring-security Migration Guide](spring-security/Migration_SpringXsuaaProjects.md) - Detailed spring-xsuaa migration
- [spring-security-legacy README](spring-security-legacy/README.md) - Legacy module documentation
- [CUSTOM_HTTP_CLIENT.md](token-client/CUSTOM_HTTP_CLIENT.md) - Custom HTTP client guide
