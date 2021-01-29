# BETA: SAP CP Spring Security Client Library

Token Validation for Spring Boot applications. It integrates [```java-security```](/java-security) to Spring Security Framework to support validations for tokens issued by these SAP Cloud Platform identity services: `xsuaa` and `identity`.

It fully integrates with [Spring Security OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver).
- The credentials from the identity services can be configured as configuration properties.
- Decodes and parses encoded JSON Web Tokens ([`Token`](/java-api/src/main/java/com/sap/cloud/security/token/Token.java)) and provides convenient access to token header parameters and claims.
- Validates the decoded token using ``java-security``security client library.

## Supported Environments
- Cloud Foundry
- Planned: Kubernetes

## Supported Identity Services
- XSUAA
- IAS (only single tenant)

## Supported Algorithms

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| RS256 | RSA256 | RSASSA-PKCS1-v1_5 with SHA-256 |


## Configuration

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
    <version>1.0.0-SNAPSHOT</version> <!-- TODO-->
</dependency>
```

#### Auto-configuration
As auto-configuration requires Spring Boot specific dependencies, it is enabled when using `xsuaa-spring-boot-starter` Spring Boot Starter. 
Then it auto-configures beans, that are required to initialize the Spring Boot application as OAuth resource server.

Auto-configuration class | Description
---- | --------
[HybridAuthorizationAutoConfiguration](/spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/HybridAuthorizationAutoConfiguration.java) | Creates a converter ([XsuaaTokenAuthorizationConverter](/spring-security/src/main/java/com/sap/cloud/security/spring/token/authentication/XsuaaTokenAuthorizationConverter.java)) that removes the xsuaa application identifier from the scope names to enable local scope checks using [Spring's common built-in expression](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#el-common-built-in) `hasAuthority`.
[HybridIdentityServicesAutoConfiguration](/spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/HybridAuthorizationAutoConfiguration.java) | Configures a `JwtDecoder` which is able to decode and validate tokens from Xsuaa and Identity service. Furthermore it registers the `XsuaaServiceConfiguration` and `IdentityServiceConfiguration` classes, that gets configured with `xsuaa.*` and `identity.*` properties.
[XsuaaTokenFlowAutoConfiguration](/spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/XsuaaTokenFlowAutoConfiguration.java) | Configures a `XsuaaTokenFlows` bean to fetch the XSUAA service binding information.

You can gradually replace auto-configurations as explained [here](https://docs.spring.io/spring-boot/docs/current/reference/html/using-boot-auto-configuration.html).


### Setup Spring Security OAuth 2.0 Resource Server
Configure your application as Spring Security OAuth 2.0 Resource Server for authentication of HTTP requests:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
    @Autowired
    Converter<Jwt, AbstractAuthenticationToken> authConverter;

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

> :bulb: Please note that the auto-configured authentication converter supports ```hasAuthority```-checks for scopes provided with the Xsuaa access token. 
> In case you need to consider authorizations provided via an OIDC token from IAS you need to overwrite the default implementation.

#### Custom Authorization Converter
Create your own Authorization Converter by implementing `Converter<Jwt, AbstractAuthenticationToken>` interface. 
In this sample it delegates to the autowired `authConverter` in case of an Xsuaa access token.
```java
class MyCustomTokenAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    public AbstractAuthenticationToken convert(Jwt jwt) {
        if(jwt.containsClaim(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE)) {
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

### Map properties to VCAP_SERVICES
In order to map the `VCAP_SERVICES` credentials to your application go to `application.xml` and provide the following configuration:
```yaml
sap.security.services:
    xsuaa:
      xsappname:    ${vcap.services.<xsuaa service instance name>.credentials.xsappname}
      uaadomain:    ${vcap.services.<xsuaa service instance name>.credentials.uaadomain}
      clientid:     ${vcap.services.<xsuaa service instance name>.credentials.clientid}
      url:          ${vcap.services.<xsuaa service instance name>.credentials.url}
    # clientsecret: ${vcap.services.<xsuaa service instance name>.credentials.clientsecret} # required for token-flows api
    
    identity:
      clientid:     ${vcap.services.<identity service instance name>.credentials.clientid}
      domain:       ${vcap.services.<identity service instance name>.credentials.domain}
      url:          ${vcap.services.<identity service instance name>.credentials.url} # can be deleted later
```  
> Note that the `<xsuaa service instance name>` and `<identity service instance name>` have to be replaced with the service instance name of the respective service instance.
	
> Enhance it with further properties you may like to access within your application like the "clientsecret". Alternatively you can also access them using `Environments.getCurrent().getXsuaaConfiguration()`.
	

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

### Get Information from `VCAP_SERVICES`
In case you need information from `VCAP_SERVICES` system environment variable, which are not exposed by `@Autowired
    XsuaaServiceConfiguration xsuaaServiceConfiguration` interface, you may need to enhance the mapped properties in your `application.yml` file as described [here](#map-properties-to-vcap_servcies).
  


### [Optional] Audit Logging
In case you have implemented a central Exception Handler as described with [Baeldung Tutorial: Error Handling for REST with Spring](https://www.baeldung.com/exception-handling-for-rest-with-spring) you may want to emit logs to the audit log service in case of `AccessDeniedException`s.

Alternatively there are also various options provided with `Spring.io`. For example, you can integrate SAP audit log service with Spring Boot Actuator audit framework as described [here](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-auditing).

### [Optional] Setup Security Context for non-HTTP requests
In case of non-HTTP requests, you may need to initialize the Spring Security Context with a JWT token you've received from a message, an event or you've requested from the identity service directly:

```java
import org.springframework.security.oauth2.jwt.JwtDecoder;public class Listener {

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

Note that Spring Security Context is thread-bound and is NOT propagated to child-threads. This [Baeldung tutorial: Spring Security Context Propagation article](https://www.baeldung.com/spring-security-async-principal-propagation) provides more information on how to propagate the context.


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
If your application binds to two XSUAA service instances (e.g. one of plan `application` and another one of plan `broker`), 
you may run into audience validation issue.

Consequently, you have to map the properties to `VCAP_SERVICES` differently. Go to `application.xml` and apply the following two changes:
1. provide instead of `sap.security.services.xsuaa` `sap.security.services.xsuaa[0]` and 
2. provide additional the client-id of the other xsuaa service(s)

Finally, it should look as following:
````yaml
 sap.security.services:
       xsuaa[0]:
            ...
       xsuaa[1]:
         clientid:  ${vcap.services.<other xsuaa service instance name>.credentials.clientid}
````

#### Configuration property name vcap.services.<<xsuaa instance name>>.credentials is not valid
We recognized that this error is raised, when your instance name contains upper cases.

## Additional (test) utilities
- [java-security-test](./java-security-test) offers test utilities to generate custom JWT tokens for the purpose of tests. It pre-configures a [WireMock](http://wiremock.org/docs/getting-started/) web server to stub outgoing calls to the identity service (OAuth resource-server), e.g. to provide token keys for offline token validation. Its use is only intended for JUnit tests.

## Samples
- [Sample](/samples/spring-security-hybrid-usage)    
demonstrating how to leverage ``spring-security`` library to secure a Spring Boot web application with tokens issued by xsuaa or identity service. Furthermore it documents how to implement SpringWebMvcTests using `java-security-test` library.


