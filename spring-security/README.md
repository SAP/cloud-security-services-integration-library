### :warning: Deprecation Notice
In alignment with the end of support for [Spring Boot 2.x](https://spring.io/projects/spring-boot#support) and [Spring Framework 5.x](https://spring.io/projects/spring-framework#support), we will also discontinue support for version 2.x for this library by the **end of 2024** and for the corresponding Spring Boot library [spring-security-starter](../spring-security-starter) by **Nov, 2023**.
Consequently, no bug fixes nor security patches will be provided beyond the designated end-of-support date.
We recommend upgrading to our [3.x major release](https://github.com/SAP/cloud-security-services-integration-library/blob/main/spring-security/), which supports Spring Boot 3.x, Spring Framework 6.x, and Java 17.

# SAP BTP Spring Security Client Library

Token Validation for Spring Boot applications. It integrates [```java-security```](/java-security) to Spring Security Framework to support validations for tokens issued by these SAP Business Technology Platform identity services: `xsuaa` and `identity`.

It fully integrates with [Spring Security OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver).
- The credentials from the identity services can be configured as configuration properties.
- Decodes and parses encoded JSON Web Tokens ([`Token`](/java-api/src/main/java/com/sap/cloud/security/token/Token.java)) and provides convenient access to token header parameters and claims.
- Validates the decoded token using ``java-security``security client library.

## Supported Environments
- Cloud Foundry
- Kubernetes/Kyma

## Supported Identity Services
- XSUAA
- IAS tokens from multiple tenants and zones

## Supported Algorithms

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| RS256 | RSA256 | RSASSA-PKCS1-v1_5 with SHA-256 |


## Configuration

### :mega: Service configuration in Kubernetes/Kyma environment 
Library supports services provisioned by [SAP BTP service-operator](https://github.com/SAP/sap-btp-service-operator) To access service instance configurations from the application, Kubernetes secrets need to be provided as files in a volume mounted on application's container.
- BTP Service-operator up to v0.2.2 - Library will look up the configuration files in the following paths:
    - XSUAA: `/etc/secrets/sapbtp/xsuaa/<YOUR XSUAA INSTANCE NAME>`
    - IAS: `/etc/secrets/sapbtp/identity/<YOUR IAS INSTANCE NAME>`
- BTP Service-operator starting from v0.2.3 - Library reads the configuration from k8s secret that is stored in a volume, this volume's `mountPath` must be defined in environment variable `SERVICE_BINDING_ROOT`.
    - upon creation of service binding a kubernetes secret with the same name as the binding is created. This binding secret needs to be stored to pod's volume.
    - `SERVICE_BINDING_ROOT` environment variable needs to be defined with value that points to volume mount's directory (`mounthPath`) where service binding secret will be stored.
      e.g. like [here](/samples/spring-security-hybrid-usage/k8s/deployment.yml#L80)

Detailed information on how to use ``spring-security`` library in Kubernetes/Kyma environment can be found in [spring-security-hybrid-usage](/samples/spring-security-hybrid-usage/README.md#deployment-on-kymakubernetes) sample README.

### Maven Dependencies
These (spring) dependencies needs to be provided:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>resourceserver-security-spring-boot-starter</artifactId>
    <version>2.17.3</version>
</dependency>
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
</dependency>
```

#### Auto-configuration
As auto-configuration requires Spring Boot specific dependencies, it is enabled when using `xsuaa-spring-boot-starter` Spring Boot Starter. 
Then it auto-configures beans, that are required to initialize the Spring Boot application as OAuth resource server.

Auto-configuration class | Description
---- | --------
[HybridAuthorizationAutoConfiguration](/spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/HybridAuthorizationAutoConfiguration.java) | Creates a converter ([XsuaaTokenAuthorizationConverter](/spring-security/src/main/java/com/sap/cloud/security/spring/token/authentication/XsuaaTokenAuthorizationConverter.java)) that removes the xsuaa application identifier from the scope names to enable local scope checks using [Spring's common built-in expression](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#el-common-built-in) `hasAuthority`.
[HybridIdentityServicesAutoConfiguration](/spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/HybridIdentityServicesAutoConfiguration.java) | Configures a `JwtDecoder` which is able to decode and validate tokens from Xsuaa and Identity service or Identity service alone. Furthermore it registers the `IdentityServiceConfiguration` and optionally `XsuaaServiceConfiguration`, that gets configured with `identity.*` and `xsuaa.*` properties.
[XsuaaTokenFlowAutoConfiguration](/spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/XsuaaTokenFlowAutoConfiguration.java) | Configures a `XsuaaTokenFlows` bean to fetch the XSUAA service binding information. Starting with `2.10.0` version it supports X.509 based authentication.
[SecurityContextAutoConfiguration](/spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/SecurityContextAutoConfiguration.java) | Configures [`JavaSecurityContextHolderStrategy`](/spring-security/src/main/java/com/sap/cloud/security/spring/token/authentication/JavaSecurityContextHolderStrategy.java) class as `SecurityContextHolderStrategy` keeps the `com.sap.cloud.security.token.SecurityContext` in sync.


#### Auto-configuration properties
Auto-configuration property | Default value | Description
---- | -------- | --------
sap.spring.security.hybrid.auto | true | This enables all auto-configurations that setup your project for hybrid IAS and XSUAA token validation.
sap.spring.security.xsuaa.flows.auto | true | This enables all auto-configurations required for xsuaa token exchange using [`token-client`](/token-client) library.

You can gradually replace auto-configurations as explained [here](https://docs.spring.io/spring-boot/docs/current/reference/html/using-boot-auto-configuration.html).


### Setup Spring Security OAuth 2.0 Resource Server
Configure your application as Spring Security OAuth 2.0 Resource Server for authentication of HTTP requests:

```java
@Configuration
@EnableWebSecurity
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, ignoreResourceNotFound = true, value = { "" }) // might be auto-configured in a future release
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
    @Autowired
    Converter<Jwt, AbstractAuthenticationToken> authConverter; // required in case of xsuaa

    @Override
    protected void configure(HttpSecurity http) throws Exception {
	// @formatter:off
	http
	.sessionManagement()
	    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	.and()
	    .authorizeRequests()
	    .antMatchers("/sayHello").hasAuthority("Read")
	    .antMatchers("/*").authenticated()
	    .anyRequest().denyAll()
	.and()
	    .oauth2ResourceServer()
	    .jwt()
	    .jwtAuthenticationConverter(authConverter); // (1) you may want to provide your own converter
	// @formatter:on
    }
}
```
> :bulb: This ``PropertySource`` might be auto-configured soon. Please watch the release notes.  
> :bulb: Please note that the auto-configured authentication converter supports ```hasAuthority```-checks for scopes provided with the Xsuaa access token. 
> In case you need to consider authorizations provided via an OIDC token from IAS you need to overwrite the default implementation.

#### Custom Authorization Converter
Create your own Authorization Converter by implementing `Converter<Jwt, AbstractAuthenticationToken>` interface. 
In this sample it delegates to the autowired `authConverter` in case of an Xsuaa access token.
```java
class MyCustomTokenAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    public AbstractAuthenticationToken convert(Jwt jwt) {
        if(jwt.containsClaim(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE)) { // required in case of xsuaa
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
... finally configure Spring's resource server with an instance of this custom converter.


## Usage

### Access user/token information
In the Java coding, use the `com.sap.cloud.security.token.Token` to extract user information from the token:

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

### Get Information from `VCAP_SERVICES`
In case you need information from `VCAP_SERVICES` system environment variable from one of the identity services, you have these options:

... in case you are bound to a single ```xsuaa``` service instance:
```java
@Autowired
XsuaaServiceConfiguration xsuaaServiceConfiguration; 
```

... in case you are bound to multiple ```xsuaa``` service instances
```java
@Autowired
XsuaaServiceConfigurations xsuaaServiceConfigurations;
```

... in case you are bound to an ```identity``` service instance
```java
@Autowired
IdentityServiceConfiguration identityServiceConfiguration;
```

Alternatively, you can also access the information with `Environments.getCurrent()`, which is provided with `java-security`.

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



## Testing

### (Test) utilities
- [java-security-test](./java-security-test) offers test utilities to generate custom JWT tokens for the purpose of tests. It pre-configures a [WireMock](http://wiremock.org/docs/getting-started/) web server to stub outgoing calls to the identity service (OAuth resource-server), e.g. to provide token keys for offline token validation. Its use is intended for JUnit tests only.

### Overwrite identity service properties
In case of local testing, there might be no ``VCAP_SERVICES`` system environment variable, or in case of JUnit testing the values may have to be overwritten. In these cases, you can set or overwrite the default property sources.

#### Minimal configuration required 
Go to `application.yml` and provide for example the following configuration:
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
    # clientsecret:  required for token-flows api
```  
	


#### ... In case of multiple XSUAA bindings
If your application binds to two XSUAA service instances (e.g. one of plan `application` and another one of plan `broker`), you may want to map the properties to `VCAP_SERVICES` for local testing. Go to `application.yml` and apply the following two changes:
1. provide instead of `sap.security.services.xsuaa` `sap.security.services.xsuaa[0]` and 
2. provide additional the client-ids of the other xsuaa service(s)

Finally, it should look as following:
````yaml
 sap.security.services:
       xsuaa[0]:
            ...     # credentials of xsuaa of plan 'application' 
       xsuaa[1]:
         clientid:  # clientid of xsuaa of plan 'broker' 
````

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
  com.sap.cloud.security: DEBUG       # set SAP-class loggers to DEBUG; set to ERROR for production setup
  org.springframework: ERROR          # set to DEBUG to see all beans loaded and auto-config conditions met
  org.springframework.security: DEBUG # set to ERROR for production setup
  org.springframework.web: DEBUG      # set to ERROR for production setup
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
- xsappname

:bulb: Example of minimal application configuration [application.yml](/samples/spring-security-hybrid-usage/src/test/resources/application.yml) for local setup.

## Samples
- [Sample](/samples/spring-security-hybrid-usage)    
demonstrating how to leverage ``spring-security`` library to secure a Spring Boot web application with tokens issued by xsuaa or identity service. Furthermore it documents how to implement SpringWebMvcTests using `java-security-test` library.


