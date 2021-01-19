# BETA: SAP CP Spring Security Client Library

Token Validation for Spring Boot applications. It integrates [```java-security```](java-security) to Spring Security Framework to support validations for tokens issued by these SAP Cloud Platform identity services: `xsuaa` and `identity`.

It fully integrates with [Spring Security OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver).
- The credentials from the identity services can be configured as configuration properties.
- Decodes and parses encoded JSON Web Tokens ([`Token`](/java-api/src/main/java/com/sap/cloud/security/token/Token.java)) and provides convenient access to token header parameters and claims.
- Validates the decoded token using ``java-security``security client library.

## Supported Environments
- Cloud Foundry
- Planned: Kubernetes

## Supported Identity Services
- XSUAA
- IAS

## Supported Algorithms

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| RS256 | RSA256 | RSASSA-PKCS1-v1_5 with SHA-256 |


## Configuration

### Maven Dependencies
These (spring) dependencies needs to be provided:
```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>spring-security</artifactId>
    <version>2.8.2</version>
</dependency>
```

### Setup Security Context for HTTP requests
Configure the OAuth resource server 
like shown in this [sample configuration](/samples/spring-security-hybrid-usage/src/main/java/sample/spring/security/SecurityConfiguration.java).

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
}
```

### Setup Security Context for non-HTTP requests
In case of non-HTTP requests, you may need to initialize the Spring Security Context with a JWT token you've received from a message / event or you've requested from the identity service directly:

```java
@EnableConfigurationProperties(XsuaaServiceConfiguration.class)
public class Listener {
     @Autowired
     XsuaaServiceConfiguration xsuaaServiceConfiguration; 
    
     public void onEvent(String encodedToken) {
        if (encodedToken != null) {
            SpringSecurityContext.init(encodedToken, jwtDecoder, xsuaaServiceConfiguration.getAppId());
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

Note that Spring Security Context is thread-bound and is NOT propagated to child-threads. This [Baeldung tutorial: Spring Security Context Propagation article](https://www.baeldung.com/spring-security-async-principal-propagation) provides more information on how to propagate the context.

## Usage

### Access user/token information
In the Java coding, use the `com.sap.cloud.security.token.Token` to extract user information:

```java
@GetMapping("/getGivenName")
public String getGivenName(@AuthenticationPrincipal Token token) {
    return token.getClaimAsString(TokenClaims.GIVEN_NAME)
}
```

> :bulb: Make sure you've imported the right Token: `com.sap.cloud.security.token.Token`.


### Check authorization on method level
Spring Security supports authorization semantics at the method level. As prerequisite you need to enable global Method Security as explained in [Baeldung tutorial: Introduction to Spring Method Security](https://www.baeldung.com/spring-security-method-security).

```java
@GetMapping("/hello-token")
@PreAuthorize("hasAuthority('Read')")
public Map<String, String> message() {
    ...
}
```

### [Optional] Audit Logging
In case you have implemented a central Exception Handler as described with [Baeldung Tutorial: Error Handling for REST with Spring](https://www.baeldung.com/exception-handling-for-rest-with-spring) you may want to emit logs to the audit log service in case of `AccessDeniedException`s.

Alternatively there are also various options provided with `Spring.io`. For example, you can integrate SAP audit log service with Spring Boot Actuator audit framework as described [here](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-auditing).


## Troubleshoot

In case you face issues, [file an issue on Github](https://github.com/SAP/cloud-security-xsuaa-integration/issues/new)
and provide these details:
- security related dependencies, get maven dependency tree with `mvn dependency:tree`
- [debug logs](#increase-log-level-to-debug)
- issue you’re facing.

### Increase log level to `DEBUG`

First, configure the Debug log level for Spring Framework Web and all Security related libs. This can be done as part of your `application.yml` or `application.properties` file.

```yaml
logging.level:
  com.sap: DEBUG                      # set SAP-class loggers to DEBUG. Set to ERROR for production setups.
  org.springframework: ERROR          # set to DEBUG to see all beans loaded and auto-config conditions met.
  org.springframework.security: DEBUG # set to ERROR for production setups. 
  org.springframework.web: DEBUG      # set to ERROR for production setups.
```

Then, in case you like to see what different filters are applied to particular request then set debug flag to true in `@EnableWebSecurity` annotation:
```java
@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
   ...
}
```

Finally, you need do re-deploy your application for the changes to take effect.

### Known issues

#### Multiple XSUAA Bindings (broker & application)  
If your application is bound to two XSUAA service instances (one of plan `application` and another one of plan `broker`), 
you may run into audience validation issue.

TODO: explain solution.

#### Configuration property name vcap.services.<<xsuaa instance name>>.credentials is not valid
We recognized that this error is raised, when your instance name contains upper cases.

## Additional (test) utilities
- [java-security-test](./java-security-test) offers test utilities to generate custom JWT tokens for the purpose of tests. It pre-configures a [WireMock](http://wiremock.org/docs/getting-started/) web server to stub outgoing calls to the identity service (OAuth resource-server), e.g. to provide token keys for offline token validation. Its use is only intended for JUnit tests.

## Samples
- [Sample](/samples/spring-security-hybrid-usage)    
demonstrating how to leverage ``spring-security`` library to secure a Spring Boot web application with tokens issued by xsuaa or identity service. Furthermore it documents how to implement SpringWebMvcTests using `java-security-test` library.


