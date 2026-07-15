# SAP BTP Spring Security Client Library (Spring Boot 3.x)

> **Note:** This module provides Spring Boot 3.x compatibility. For Spring Boot 4.x, use the [`spring-security`](../spring-security) module instead.

This module provides the same API and functionality as [`spring-security`](../spring-security), but is compatible with:
- Spring Boot 3.5.9
- Spring Framework 6.2.15
- Spring Security 6.5.7

## Documentation

**All documentation from [`spring-security`](../spring-security/README.md) applies to this module**, with the following differences:

### Maven Dependencies

Use the Spring Boot 3.x starter instead:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>resourceserver-security-spring-boot-3-starter</artifactId>
    <version>4.1.0</version>
</dependency>
```

### HTTP Client

This module uses Apache HttpClient 4.5 for HTTP communication (same as version 3.x of the library).

The main `spring-security` module (for Spring Boot 4.x) uses Java 11 HttpClient instead.

### Samples

Example application using this module:
- [Spring Webflux Hybrid Usage](../samples/spring-webflux-security-hybrid-usage) - Demonstrates reactive security with Spring Boot 3.x

## Migration

This module is a **temporary compatibility layer** for applications not yet ready to upgrade to Spring Boot 4.x.

Please upgrade to Spring Boot 4.x and the [`spring-security`](../spring-security) module as soon as possible.

See [MIGRATION_4.0.md](../MIGRATION_4.0.md) for migration instructions.

## Distributed Cache Auto-Configuration (since 4.1.0)

To share the SAP Cloud Security caches across a horizontally-scaled deployment, enable the auto-configuration:

```yaml
sap:
  security:
    cache:
      distributed:
        enabled: true
        # cache-name: sap-security  # default; override to reuse another cache
```

Then expose either a `SecurityCache<String,String>` bean directly or a Spring `CacheManager` whose cache called `sap-security` is backed by your distributed store:

```java
@Configuration
public class DistributedCacheConfig {
    @Bean
    public CacheManager cacheManager(RedisConnectionFactory rcf) {
        return RedisCacheManager.builder(rcf).initialCacheNames(Set.of("sap-security")).build();
    }
}
```

The auto-config picks that up and wires it into:
- `XsuaaTokenFlows` — outbound token cache (namespace `tokens`).
- `JwtValidatorBuilder` (via `withSecurityCache`) — JWKS and OIDC caches (namespaces `jwks`, `oidc`).

Discovery order: (1) user `SecurityCache` bean → (2) Spring `CacheManager.getCache(name)` → (3) `javax.cache.CacheManager.getCache(name, String.class, String.class)` → (4) no-op (WARN in logs).

See the top-level [README](../README.md#25-distributed-caching-since-410) for the complete story including opt-in decode / signature caches.

## Complete Documentation

For complete documentation on usage, configuration, testing, and troubleshooting, see:
- [`spring-security` README](../spring-security/README.md) - All documentation applies unless noted above
- [MIGRATION_4.0.md](../MIGRATION_4.0.md) - Migration guide from version 3.x to 4.0.1
