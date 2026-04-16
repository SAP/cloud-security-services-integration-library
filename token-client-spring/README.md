# Token Client Spring

This module provides **Spring-based implementations** for the XSUAA Token Client library.

## Description

The `token-client-spring` module contains Spring-specific implementations that use Spring's `RestTemplate` for HTTP communication:

- **SpringOAuth2TokenKeyService** - Spring RestTemplate-based implementation for retrieving token keys
- **SpringOidcConfigurationService** - Spring-based OIDC configuration service
- **XsuaaOAuth2TokenService** - Spring RestTemplate-based token service implementation

## When to Use This Module

Use `token-client-spring` if:
- You're building a **Spring application**
- You want to use Spring's `RestTemplate` for HTTP communication
- You need Spring-specific OAuth2 implementations

**Note:** This module depends on `token-client-core`, so you'll get all core functionality as well.

## Maven Dependency

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client-spring</artifactId>
    <version>3.6.13</version>
</dependency>
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-web</artifactId>
</dependency>
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
</dependency>
```

## Key Classes

- `SpringOAuth2TokenKeyService` - Retrieves token keys using Spring's RestTemplate
- `SpringOidcConfigurationService` - Retrieves OIDC configuration using Spring
- `XsuaaOAuth2TokenService` - Spring-based token service with RestTemplate

## Usage in Spring Applications

For Spring Boot applications, it's recommended to use the autoconfiguration provided by:

```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>resourceserver-security-spring-boot-starter</artifactId>
    <version>3.6.13</version>
</dependency>
```

This automatically configures `XsuaaTokenFlows` with the appropriate Spring-based implementations.

### Manual Spring Configuration

If you need to configure manually:

```java
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class TokenClientConfiguration {
    
    @Bean
    public XsuaaTokenFlows xsuaaTokenFlows(OAuth2ServiceConfiguration config) {
        RestTemplate restTemplate = new RestTemplate();
        
        return new XsuaaTokenFlows(
            new XsuaaOAuth2TokenService(restTemplate),
            new XsuaaDefaultEndpoints(config),
            config.getClientIdentity()
        );
    }
}
```

## Documentation

For complete documentation, configuration options, and examples, see the main [Token Client README](../token-client/README.md).

## Module Structure

This module is part of the token-client split:
- **token-client-core** - Plain Java implementation (this module depends on it)
- **token-client-spring** (this module) - Spring-specific implementations
- **token-client** - Wrapper module including both for backward compatibility

## Dependencies

This module has the following key dependencies:
- `token-client-core` - Core token client functionality
- `spring-web` (provided) - Spring's web support including RestTemplate
- `javax.annotation-api` - For `@Nonnull` annotations
