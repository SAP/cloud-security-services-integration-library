# Token Client Core

This module provides the core functionality of the XSUAA Token Client library **without Spring dependencies**.

## Description

The `token-client-core` module contains all essential token client features implemented in plain Java:

- **Token Flow Implementations**: JWT Bearer, Client Credentials, Refresh Token, Password flows
- **HTTP Client Factory**: Default implementation for Apache HttpClient configuration
- **OAuth2 Token Services**: Token retrieval and caching functionality
- **Token Cache**: Configurable caching mechanism for tokens
- **Retry Mechanism**: Automatic retry for failed requests
- **XSUAA Integration**: Endpoints, token extensions, and utilities

## When to Use This Module

Use `token-client-core` if:
- You're building a **Java EE application** without Spring
- You want to **avoid Spring dependencies** in your application
- You only need the core token client functionality

## Maven Dependency

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client-core</artifactId>
    <version>3.6.13</version>
</dependency>
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
</dependency>
```

## Key Classes

- `XsuaaTokenFlows` - Main API for executing token flows
- `DefaultOAuth2TokenService` - Token service implementation with caching
- `DefaultHttpClientFactory` - Factory for creating configured HTTP clients
- `OAuth2ServiceConfiguration` - Configuration holder for Identity service
- `TokenCacheConfiguration` - Cache configuration and management

## Usage Example

```java
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.Environments;

// Initialize configuration
OAuth2ServiceConfiguration config = Environments.getCurrent().getXsuaaConfiguration();

// Create HTTP client
CloseableHttpClient httpClient = HttpClientFactory.createClient(config.getClientIdentity());

// Initialize token flows
XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
    new DefaultOAuth2TokenService(httpClient),
    new XsuaaDefaultEndpoints(config),
    config.getClientIdentity()
);

// Use token flows
OAuth2TokenResponse token = tokenFlows.clientCredentialsTokenFlow()
    .execute();
```

## Documentation

For complete documentation, configuration options, and examples, see the main [Token Client README](../token-client/README.md).

## Module Structure

This module is part of the token-client split:
- **token-client-core** (this module) - Plain Java implementation
- **token-client-spring** - Spring-specific implementations
- **token-client** - Wrapper module including both for backward compatibility
