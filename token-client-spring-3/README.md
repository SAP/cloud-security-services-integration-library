# Token Client Spring 3

This module provides Spring-based implementations of the OAuth2 token service interfaces from the [token-client](../token-client) module, compiled against **Spring Framework 6.x** for **Spring Boot 3.x** compatibility.

## Overview

This module is the Spring Boot 3.x compatible version of [token-client-spring](../token-client-spring). Use this module if your application uses Spring Boot 3.x (Spring Framework 6.x).

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
    <artifactId>token-client-spring-3</artifactId>
    <version>4.0.2</version>
</dependency>
```

**Note:** This module has `spring-web` (6.x) as a `provided` dependency. Your application must include Spring Web in its classpath.

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
- Your application uses **Spring Boot 3.x** (not 4.x)
- You need Spring RestOperations integration for token flows

For Spring Boot 4.x applications, use [token-client-spring](../token-client-spring) instead.

For most use cases, the default `DefaultOAuth2TokenService` from `token-client` (using Java 11 HttpClient) is recommended as it has no external dependencies.
