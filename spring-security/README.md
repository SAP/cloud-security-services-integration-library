# SAP BTP Spring Security Client Library

This project provides validation of tokens issued by SAP BTP Identity service or XSUAA for Spring Boot applications.

It fully integrates [```java-security```](../java-security) with [Spring Security OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/reference/) by providing the following key features:

* Automatic OAuth2 service configuration based on SAP BTP service bindings found in the environment
* OAuth2 Token Validation based on these service configurations
* Easy access to principal and token claims within request handlers
* Fetch XSUAA tokens with different Grant types

#### Supported Environments
- Cloud Foundry
- Kubernetes/Kyma

#### Supported Identity Services
- SAP Identity service, supports Multitenancy/multiple zones
- XSUAA

#### Supported Algorithms

| JWS     | Algorithm | Description                    |
|---------|-----------|--------------------------------|
| RS256   | RSA256    | RSASSA-PKCS1-v1_5 with SHA-256 |

## Requirements
- Java 17
- Spring Boot 3
- Spring Framework 6
- [Apache HttpClient 4.5](https://hc.apache.org/httpcomponents-client-4.5.x/index.html)

## Table of Contents
* [Setup](#setup)
  + [Maven Dependencies](#maven-dependencies)
  + [Autoconfiguration](#autoconfiguration)
  + [SecurityConfiguration](#security-configuration)
  + [Service configuration in Kubernetes environment](#service-configuration-in-kuberneteskyma-environment)
* [Usage](#usage)
  + [Securing Endpoints](#securing-endpoints)
  + [Securing Methods](#securing-methods)
  + [Access token information](#access-token-information)
  + [Token Exchange Configuration](#token-exchange-configuration)
  + [Fetch XSUAA Tokens](#fetch-xsuaa-tokens)
  + [Access service configurations](#access-service-configurations)
* [Optional Usage](#optional-usage)
  + [[Optional] Audit Logging](#optional-audit-logging)
  + [[Optional] Setup Security Context for non-HTTP requests](#optional-setup-security-context-for-non-http-requests)
  + [[Optional] Reactive Usage with Webflux](#optional-reactive-usage-with-webflux)
* [Testing](#testing)
  + [JUnit](#junit)
  + [Overriding identity service configurations](#overriding-identity-service-configurations)
  + [Local testing](#local-testing)
* [Troubleshooting](#troubleshooting)
   + [Set debug log level](#set-debug-log-level)
   + [Common pitfalls](#common-pitfalls)
* [Samples](#samples)


## Setup

### Maven Dependencies
These (spring) dependencies need to be provided:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>resourceserver-security-spring-boot-starter</artifactId>
    <version>3.6.5</version>
</dependency>
```

### Autoconfiguration
By using `resourceserver-security-spring-boot-starter`, beans that are required to initialize the Spring Boot application as OAuth resource server are autoconfigured.

The integration into Spring Security is done by providing a bean of type [JwtDecoder](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/jwt/JwtDecoder.html) that overrides the default of the Spring framework.
Depending on the service bindings in the environment, a different implementation is used to support both SAP Identity Service and XSUAA.\
In addition, a bean of type [XsuaaTokenFlows](../token-client/src/main/java/com/sap/cloud/security/xsuaa/tokenflows/XsuaaTokenFlows.java) is provided that can be used to fetch XSUAA tokens.

#### Autoconfiguration classes
| Autoconfiguration class                                                                                                                          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|--------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [HybridAuthorizationAutoConfiguration](./src/main/java/com/sap/cloud/security/spring/autoconfig/HybridAuthorizationAutoConfiguration.java)       | Creates a converter ([XsuaaTokenAuthorizationConverter](./src/main/java/com/sap/cloud/security/spring/token/authentication/XsuaaTokenAuthorizationConverter.java)) that removes the XSUAA application identifier from the scope names, allowing local scope checks to be performed using [Spring's common built-in expression](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#el-common-built-in) `hasAuthority`. Supports only single Xsuaa binding |
| [HybridIdentityServicesAutoConfiguration](./src/main/java/com/sap/cloud/security/spring/autoconfig/HybridIdentityServicesAutoConfiguration.java) | Configures a `JwtDecoder` which is able to decode and validate tokens from Xsuaa and/or Identity service<br/>Furthermore it registers `IdentityServiceConfiguration` and optionally `XsuaaServiceConfiguration`, that allow overriding the identity service configurations found in the service bindings (via `identity.*` and `xsuaa.*` properties).                                                                                                                          |
| [XsuaaTokenFlowAutoConfiguration](./src/main/java/com/sap/cloud/security/spring/autoconfig/XsuaaTokenFlowAutoConfiguration.java)                 | Configures an `XsuaaTokenFlows` bean to fetch the XSUAA tokens. Starting with `2.10.0` version it supports X.509 based authentication                                                                                                                                                                                                                                                                                                                                          |
| [SecurityContextEnvironmentPostProcessor](./src/main/java/com/sap/cloud/security/spring/autoconfig/SecurityContextEnvironmentPostProcessor.java)               | Configures [`JavaSecurityContextHolderStrategy`](./src/main/java/com/sap/cloud/security/spring/token/authentication/JavaSecurityContextHolderStrategy.java) to be used as `SecurityContextHolderStrategy` to keep the `com.sap.cloud.security.token.SecurityContext` in sync                                                                                                                                                                                                   |

#### Autoconfiguration properties
| Autoconfiguration property              | Default value | Description                                                                                                             |
|-----------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------|
| sap.spring.security.hybrid.auto         | true        | This enables all auto-configurations that setup your project for hybrid IAS and/or XSUAA token validation.              |
| sap.spring.security.xsuaa.flows.auto    | true        | This enables all auto-configurations required for XSUAA token exchange using [`token-client`](../token-client) library. |
| sap.spring.security.identity.prooftoken | true        | This creates a `JwtDecoder` for identity service with enabled prooftoken check                                          |
| sap.spring.security.hybrid.token.exchange.mode | disabled | Token exchange mode: `disabled`, `provide_xsuaa`, `force_xsuaa` |

You can gradually replace auto-configurations as explained [here](https://docs.spring.io/spring-boot/docs/current/reference/html/using-boot-auto-configuration.html).

#### Multiple Xsuaa configurations
:warning: In case of multiple Xsuaa configurations, the [XsuaaTokenAuthorizationConverter](./src/main/java/com/sap/cloud/security/spring/token/authentication/XsuaaTokenAuthorizationConverter.java) bean is not autoconfigured.
The bean needs to be created manually based on the service configuration you want the converter to be initialized with.

For example, to create a converter that removes the application identifier of the *first* XSUAA configuration from the scope names, you could create the following bean:

```java
@Bean
public Converter<Jwt, AbstractAuthenticationToken> xsuaaAuthConverter(XsuaaServiceConfigurations xsuaaConfigs) {
	return new XsuaaTokenAuthorizationConverter(xsuaaConfigs.getConfigurations().get(0).getProperty(APP_ID));
}
```

A further example can be
found [here](../samples/spring-security-hybrid-usage/src/main/java/sample/spring/security/XsuaaAuthzConverter.java).

You may want to filter the list accessible via `XsuaaServiceConfigurations#getConfigurations` based on the configuration
properties to find a specific configuration from the list.

### Security Configuration
This is an example how to configure your application as Spring Security OAuth 2.0 Resource Server for authentication of HTTP requests:

```java
@Configuration
@EnableWebSecurity
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, ignoreResourceNotFound = true, value = { "" })
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    Converter<Jwt, AbstractAuthenticationToken> authConverter; // only required for XSUAA

    @Override
    protected void configure(HttpSecurity http) throws Exception {
	http
	.sessionManagement()
	    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	.and()
	    // ... secure endpoints based on Authorities ...
	.and()
	    .oauth2ResourceServer()
	    .jwt()
	    .jwtAuthenticationConverter(authConverter); // (1) you may want to provide your own converter
    }
}
```

> :bulb: Please note that the autoconfigured authentication converter only supports ```hasAuthority```-checks for scopes provided with the Xsuaa access token.
> In case you need to consider authorizations provided via an OIDC token from IAS you need to provide your own converter instead.

#### Custom Authorization Converter
You may want to configure the security chain with your own Authorization Converter by implementing the `Converter<Jwt, AbstractAuthenticationToken>` interface.
Here is an example implementation that provides authorities based on Identity service groups.
The leading prefix "IASAUTHZ_" is removed for easier authorization checks.\
The implementation delegates to the default `authConverter` in case of an Xsuaa access token.
In this sample, it is expected to be autowired in the configuration class in which you define your converter.

```java
class MyCustomTokenAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    public AbstractAuthenticationToken convert(Jwt jwt) {
        if(jwt.containsClaim(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE)) { // required in case of XSUAA
            return authConverter.convert(jwt); // @Autowired Converter<Jwt, AbstractAuthenticationToken> authConverter;
        }
        return new AuthenticationToken(jwt, deriveAuthoritiesFromGroup(jwt));
    }

    private Collection<GrantedAuthority> deriveAuthoritiesFromGroup(Jwt jwt) {
        Collection<GrantedAuthority> groupAuthorities = new ArrayList<>();
        if (jwt.containsClaim(TokenClaims.GROUPS)) {
            List<String> groups = jwt.getClaimAsStringList(TokenClaims.GROUPS);
            for (String group: groups) {
                groupAuthorities.add(new SimpleGrantedAuthority(group.replace("IASAUTHZ_", "")));
            }
        }
        return groupAuthorities;
    }
}
```

### Service configuration in Kubernetes/Kyma environment
Starting with version 2.13.0, the service bindings are read with [btp-environment-variable-access](https://github.com/SAP/btp-environment-variable-access).
Please adhere to the guidelines outlined [here](https://github.com/SAP/btp-environment-variable-access#kubernetes-specifics) for configuring K8s secrets for the bound service configurations.
An example how to use ``spring-security`` library in Kubernetes/Kyma environment can be found in [spring-security-hybrid-usage](../samples/spring-security-hybrid-usage/README.md).

Generally, the library supports out of the box services provisioned by [SAP BTP service-operator](https://github.com/SAP/sap-btp-service-operator).
To access service instance configurations from the application, Kubernetes secrets need to be provided as files in a volume mounted on application's container.

- BTP Service-operator up to v0.2.2 - Library will look up the configuration files in the following paths:
  - XSUAA: `/etc/secrets/sapbtp/xsuaa/<YOUR XSUAA INSTANCE NAME>`
  - Identity Services: `/etc/secrets/sapbtp/identity/<YOUR IDENTITY SERVICE INSTANCE NAME>`
- BTP Service-operator starting from v0.2.3 - Library reads the configuration from k8s secret that is stored in a volume, this volume's `mountPath` must be defined in environment variable `SERVICE_BINDING_ROOT`.
  - Upon creation of the service binding, a Kubernetes secret with the same name as the binding is created. This binding secret needs to be stored to pod's volume.
  - The `SERVICE_BINDING_ROOT` environment variable needs to be defined with a value that points to volume mount's directory (`mounthPath`) where the service binding secret will be stored.
    e.g. like [here](../samples/spring-security-hybrid-usage/k8s/deployment.yml#L80).

## Usage
### Securing Endpoints
Controller endpoints can be secured based on the Authorities extracted by the Authorization Converter.\
> :exclamation: Never forget to finish your matcher chain with .anyRequest().denyAll()

For instance, to secure endpoint `/helloWorld` for users with authority "Read".

```java
@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests(authz ->
                        authz
                            .requestMatchers("/helloWorld").hasAuthority("Read")
                            .anyRequest().denyAll())
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(<yourAuthorizationConverter>)
        return http.build();
    }
```

### Securing Methods
Spring Security supports authorization semantics at the method level. As prerequisite you need to enable global Method Security as explained in [Baeldung tutorial: Introduction to Spring Method Security](https://www.baeldung.com/spring-security-method-security).

```java
@GetMapping("/hello-token")
@PreAuthorize("hasAuthority('Read')")
public Map<String, String> message() {
...
}
```

### Access token information
You can use the `@AuthenticationPrincipal` annotation to inject a [Token](../java-api/src/main/java/com/sap/cloud/security/token/Token.java) object into your request handlers.
It provides different methods to access the token information, e.g. to extract user information:

```java
@GetMapping("/getGivenName")
public String getGivenName(@AuthenticationPrincipal Token token) {
    return token.getClaimAsString(TokenClaims.GIVEN_NAME)
}
```

> :bulb: Make sure you've imported the right Token: `com.sap.cloud.security.token.Token`. There is more than one Token interface in this repository.


### Fetch XSUAA Tokens
Please refer to the [token-client](../token-client/README.md) documentation for information on how to use the provided `XsuaaTokenFlows` bean to fetch XSUAA tokens.

### Access service configurations
In case you need information from the service binding configuration from one of the identity services, you have these options:

- in case you are bound to a single ```XSUAA``` service instance:
  ```java
  @Autowired
  XsuaaServiceConfiguration xsuaaServiceConfiguration;
  ```

- in case you are bound to multiple ```XSUAA``` service instances
  ```java
  @Autowired
  XsuaaServiceConfigurations xsuaaServiceConfigurations;
  ```

- in case you are bound to an ```identity``` service instance
  ```java
  @Autowired
  IdentityServiceConfiguration identityServiceConfiguration;
  ```

Alternatively, you can also access the information with `Environments.getCurrent()`, which is provided with `java-security`.

### Token Exchange Configuration

The library supports automatic token exchange between IAS and XSUAA tokens in hybrid authentication scenarios.

**Enable Token Exchange via Configuration**:

```yaml
# application.yml
sap:
  spring:
    security:
      hybrid:
        token:
          exchange:
            mode: provide_xsuaa  # Options: disabled, provide_xsuaa, force_xsuaa (default: disabled)
```

**Spring Security Configuration**:

```java

@EnableWebSecurity
public class SecurityConfig {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt());
        // Uses auto-configured HybridJwtDecoder
    }
}
```

**How It Works**:

1. [
   `HybridIdentityServicesAutoConfiguration`](spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/HybridIdentityServicesAutoConfiguration.java)
   detects IAS + XSUAA bindings
2. Creates [
   `HybridJwtDecoder`](spring-security/src/main/java/com/sap/cloud/security/spring/token/authentication/HybridJwtDecoder.java)
   bean with configured mode
3. Registers [`IdTokenExtension`](java-api/src/main/java/com/sap/cloud/security/token/IdTokenExtension.java) and [
   `XsuaaTokenExtension`](java-api/src/main/java/com/sap/cloud/security/token/XsuaaTokenExtension.java) in [
   `SecurityContext`](java-api/src/main/java/com/sap/cloud/security/token/SecurityContext.java)
4. Spring Security uses decoder for all JWT validation

**Access Tokens in Application Code**:

```java

@RestController
public class ApiController {

    @GetMapping("/api/resource")
    public String getResource(@AuthenticationPrincipal Jwt jwt) {
      // In FORCE_XSUAA mode: SecurityContext.getToken() returns exchanged XSUAA token
      //                       SecurityContext.getXsuaaToken() returns exchanged XSUAA token
      // In PROVIDE_XSUAA mode: SecurityContext.getToken() returns IAS token
      //                       SecurityContext.getXsuaaToken() returns exchanged XSUAA token
      // No matter the mode, SecurityContext.getXsuaaToken() always returns the XSUAA token, even if the incoming token was an XSUAA token.

      Token xsuaaToken = SecurityContext.getXsuaaToken(); // Always available if exchange enabled
        List<String> scopes = xsuaaToken.getClaimAsStringList("scope");

        return "Resource accessed";
    }
}
```

## Optional Usage
<details>
<summary>Show optional usage instructions</summary>

### [Optional] Audit Logging
In case you have implemented a central Exception Handler as described with [Baeldung Tutorial: Error Handling for REST with Spring](https://www.baeldung.com/exception-handling-for-rest-with-spring) you may want to emit logs to the audit log service in case of `AccessDeniedException`s.

Alternatively there are also various options provided with `Spring.io`. For example, you can integrate SAP audit log service with Spring Boot Actuator audit framework as described [here](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-auditing).

### [Optional] Setup Security Context for non-HTTP requests
In case of non-HTTP requests, you may need to initialize the Spring Security Context with a JWT token you've received from a message, an event or you've requested from the identity service directly:

```java
import org.springframework.security.oauth2.jwt.JwtDecoder;

public class Listener {

     @Autowired
     JwtDecoder jwtDecoder;

     @Autowired
     Converter<Jwt, AbstractAuthenticationToken> authConverter;


     public void onEvent(String encodedToken) {
        if (encodedToken != null) {
            SpringSecurityContext.init(encodedToken, jwtDecoder, authConverter);
        }
        try {
            handleEvent();
        } finally {
            SpringSecurityContext.clear();
        }
    }
}
```
In detail `com.sap.cloud.security.token.SpringSecurityContext` wraps the Spring Security Context (namely `SecurityContextHolder.getContext()`), which stores by default the information in `ThreadLocal`s. In order to avoid memory leaks it is recommended to remove the current thread's value for garbage collection.

> :bulb: Note that ``SpringSecurityContext`` is **thread-bound** and is NOT propagated to child-threads. This [Baeldung tutorial: Spring Security Context Propagation article](https://www.baeldung.com/spring-security-async-principal-propagation) provides more information on how to propagate the context.

### [Optional] Reactive Usage with Webflux
In case you want to implement a reactive token authentication flow, you can use the [ReactiveHybridJwtDecoder](./src/main/java/com/sap/cloud/security/spring/token/authentication/ReactiveHybridJwtDecoder.java) and the [ReactiveSecurityContext](./src/main/java/com/sap/cloud/security/spring/token/ReactiveSecurityContext.java). The reactive authentication flow allows to build non-blocking, asynchronous and event-driven applications.
</details>


## Testing

### JUnit
We recommend [java-security-test](../java-security-test) to write JUnit tests for the security layer of your application that runs without a real identity service instance.\
It offers test utilities to generate custom JWT tokens for the purpose of tests.
It pre-configures a [WireMock](http://wiremock.org/docs/getting-started/) web server to stub outgoing calls to the identity service, e.g. to provide token keys for offline token validation.

### Overriding identity service configurations
If you need to manually configure the identity service configuration, e.g. to target the mocked OAuth2 server from `java-security-test`, you can override the values read from the service bindings by setting the Spring properties `sap.security.services.identity` or `sap.security.services.xsuaa`.

#### java-security-test configuration
In an `application.yml` the test configuration suitable for use with `java-security-test` would look as follows:

```yaml
sap.security.services:
    identity:
      clientid:  sb-clientId!t0815  # SecurityTest.DEFAULT_CLIENT_ID
      domains:
        - localhost                 # SecurityTest.DEFAULT_DOMAIN
    xsuaa:
      xsappname: xsapp!t0815        # SecurityTest.DEFAULT_APP_ID
      uaadomain: localhost          # SecurityTest.DEFAULT_DOMAIN
      clientid:  sb-clientId!t0815  # SecurityTest.DEFAULT_CLIENT_ID
      url:       http://localhost   # SecurityTest.DEFAULT_URL
```

#### Multiple XSUAA bindings

If you need to manually configure the application for more than one XSUAA service instances (e.g. one of
plan `application` and another one of plan `broker`).

````yaml
 sap.security.services:
   xsuaa[0]:
     ...     # credentials of XSUAA of plan 'application'
   xsuaa[1]:
     clientid:  # clientid of XSUAA of plan 'broker'
````

:warning: Autoconfiguration for multiple Xsuaa service instance bindings is not available for
the [Converter bean](https://github.com/SAP/cloud-security-services-integration-library/blob/main/spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/HybridAuthorizationAutoConfiguration.java#L46).
You will need to provide it manually. An example can be
found [here](../samples/spring-security-hybrid-usage/src/main/java/sample/spring/security/XsuaaAuthzConverter.java).

### Local testing
To run or debug your secured application locally you need to provide the mandatory Xsuaa or Identity service configuration attributes prior to launching the application.
There are two ways how to provide the service configuration to your Spring Boot application:
1. As Spring properties in `application.yaml` or `application.properties` files

   The security library requires the following key value pairs to start successfully:
   - For Xsuaa
     ```yaml
      sap.security.services:
         xsuaa:
           xsappname: xsapp!t0815        # SecurityTest.DEFAULT_APP_ID
           uaadomain: localhost          # SecurityTest.DEFAULT_DOMAIN
           clientid:  sb-clientId!t0815  # SecurityTest.DEFAULT_CLIENT_ID
           url:       http://localhost   # SecurityTest.DEFAULT_URL
     ```
   - For Identity service
     ```yaml
       sap.security.services:
           identity:
             clientid:  sb-clientId!t0815  # SecurityTest.DEFAULT_CLIENT_ID
             domains:
               - localhost                 # SecurityTest.DEFAULT_DOMAIN
       ```

   :bulb: The provided values above correspond with the [JwtGenerator](../java-security-test/src/main/java/com/sap/cloud/security/test/JwtGenerator.java) default values from `java-security-test` library, meaning you can generate tokens and test them with this service configuration.

2. As `VCAP_SERVICES` environment variable
    The value of the `VCAP_SERVICES` environment variable needs to be in the following format
   ```json
   {"xsuaa": [
                {
                  "credentials": {
                          "clientid": "sb-clientId!t0815",
                          "xsappname": "xsapp!t0815",
                          "uaadomain": "localhost",
                          "url": "https://localhost"
                  }
                }
             ]
   }
   ```
> :bulb: To evaluate your application using an actual Identity service, you can obtain the service configuration information from the Identity or Xsuaa service instance created in the SAP BTP Cockpit.
> Then, use this data to populate the application.yml or the VCAP_SERVICES environment variable.


## Troubleshooting
In case you face issues, [submit an issue on GitHub](https://github.com/SAP/cloud-security-services-integration-library/issues/new/choose)
and include the following details:
- any security-related dependencies used including version, get maven dependency tree with `mvn dependency:tree`
- [debug logs](#set-debug-log-level)
- issue you’re facing.

### Set Debug Log Level

First, configure the Debug log level for Spring Framework Web and all Security related libs. This can be done as part of your `application.yml` or `application.properties` file.

```yaml
logging.level:
  com.sap.cloud.security: DEBUG       # set SAP-class loggers to DEBUG; set to ERROR for production setup
  org.springframework: ERROR          # set to DEBUG to see all beans loaded and autoconfig conditions met
  org.springframework.security: DEBUG # set to ERROR for production setup
  org.springframework.web: DEBUG      # set to ERROR for production setup
```

Then, in case you want to view the various filters applied to a specific request, you can enable the debug flag by setting it to true in the `@EnableWebSecurity` annotation:
```java
@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
   // ...
}
```

:bulb: Remember to restage your application for the changes to take effect.

### Common pitfalls

#### Configuration property name vcap.services.<<xsuaa instance name>>.credentials is not valid
We recognized that this error is raised, when your instance name contains upper cases.

#### Local setup fails with "APPLICATION FAILED TO START"
When you're trying to run the application locally, but application fails to start with the following error message:
```log
org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type 'org.springframework.core.convert.converter.Converter<org.springframework.security.oauth2.jwt.Jwt, org.springframework.security.authentication.AbstractAuthenticationToken>' available: expected at least 1 bean which qualifies as autowire candidate. Dependency annotations: {@org.springframework.beans.factory.annotation.Autowired(required=true)}

***************************
APPLICATION FAILED TO START
***************************
Field authConverter in com.sap.cloud.test.SecurityConfiguration required a bean of type 'org.springframework.core.convert.converter.Converter' that could not be found.
```
Make sure that you have defined the following mandatory attribute in the service configuration (VCAP_SERVICES env variable or application.yaml or application.properties)
- for Xsuaa
  - xsappname
  - uaadomain
  - clientid
  - url
- for Identity service
  - domains
  - clientid

:bulb: Example of minimal application configuration [application.yml](../samples/spring-security-hybrid-usage/src/test/resources/application.yml) for local setup.

##### Multiple Xsuaa service bindings

Autoconfiguration for multiple Xsuaa service instance bindings is not available for
the [Converter bean](https://github.com/SAP/cloud-security-services-integration-library/blob/main/spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/HybridAuthorizationAutoConfiguration.java#L46).
You will need to provide it manually. An example can be
found [here](../samples/spring-security-hybrid-usage/src/main/java/sample/spring/security/XsuaaAuthzConverter.java).

## Samples
- [Hybrid Usage](../samples/spring-security-hybrid-usage)
Demonstrates how to leverage ``spring-security`` library to secure a Spring Boot web application with tokens issued by SAP Identity service or XSUAA. Furthermore, it documents how to implement Spring WebMvcTests using `java-security-test` library.
- [Basic Auth Usage](../samples/spring-security-basic-auth)
Legacy example that demonstrates how to leverage ``spring-security`` library to secure a Spring Boot web application with username/password provided via Basic Auth header. Furthermore, it documents how to implement Spring WebMvcTests using `java-security-test` library.
- [Webflux Hybrid Usage](../samples/spring-webflux-security-hybrid-usage)\
Shows how to use ``spring-security`` library with both tokens issued by XSUAA and SAP Identity service in an reactive environment.
