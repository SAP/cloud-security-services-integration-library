# Token Client Spring

This module provides Spring-based implementations of the OAuth2 token service interfaces from the [token-client](../token-client) module, compiled against **Spring Framework 7.x** for **Spring Boot 4.x**.

## Overview

Starting with version 4.0.0, Spring-specific implementations have been moved to this separate module to avoid classloader issues when `token-client` is used in environments where Spring is not available (e.g., SAP Java Buildpack's Tomcat lib folder).

**Important:** This module is compiled against Spring Framework 7.x (Spring Boot 4.x). For Spring Boot 3.x compatibility, use [token-client-spring-3](../token-client-spring-3) instead.

| Module | Spring Boot | Spring Framework |
|--------|-------------|------------------|
| `token-client-spring` | 4.x | 7.x |
| `token-client-spring-3` | 3.x | 6.x |

## Classes

| Class | Description |
|-------|-------------|
| `XsuaaOAuth2TokenService` | Spring RestOperations-based implementation of `OAuth2TokenService` for token retrieval |
| `SpringOAuth2TokenKeyService` | Spring RestOperations-based implementation of `OAuth2TokenKeyService` for token key retrieval |
| `SpringOidcConfigurationService` | Spring RestOperations-based implementation of `OidcConfigurationService` for OIDC discovery |

## Maven Dependency

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client-spring</artifactId>
    <version>4.0.2</version>
</dependency>
```

**Note:** This module has `spring-web` as a `provided` dependency. Your application must include Spring Web in its classpath.

## Usage

These classes require a Spring `RestOperations` instance (e.g., `RestTemplate`):

```java
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import org.springframework.web.client.RestTemplate;

RestTemplate restTemplate = new RestTemplate();
XsuaaOAuth2TokenService tokenService = new XsuaaOAuth2TokenService(restTemplate);
```

## When to Use

Use this module if:
- Your application uses **Spring Boot 4.x** (Spring Framework 7.x)
- You need Spring RestOperations integration for token flows
- Your application already uses Spring and you want to reuse existing `RestTemplate` configuration

For Spring Boot 3.x applications, use [token-client-spring-3](../token-client-spring-3) instead.

For most use cases, the default `DefaultOAuth2TokenService` from `token-client` (using Java 11 HttpClient) is recommended as it has no external dependencies.

## Migration from token-client 3.x

If you were using `XsuaaOAuth2TokenService`, `SpringOAuth2TokenKeyService`, or `SpringOidcConfigurationService` from `token-client` in version 3.x, you now need to add this module as a dependency:

```xml
<!-- Add this dependency -->
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client-spring</artifactId>
    <version>4.0.2</version>
</dependency>
```

No code changes are required - the classes remain in the same package (`com.sap.cloud.security.xsuaa.client`).
