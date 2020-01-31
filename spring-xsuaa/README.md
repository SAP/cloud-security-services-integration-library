# XSUAA Security 

## Integrate in a OAuth resource server

This library enhances the [spring-security](https://github.com/spring-projects/spring-security/) project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. A Spring boot application needs a security configuration class that enables the resource server and configures authentication using JWT tokens.

## Configuration

These (spring) dependencies needs to be provided:

### Maven Dependencies
```xml
<dependency> <!-- includes spring-security-oauth2 -->
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>spring-xsuaa</artifactId>
    <version>2.4.2-SNAPSHOT</version>
</dependency>
<dependency> <!-- new with version 1.5.0 -->
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-to-slf4j</artifactId>
    <version>2.11.2</version>
</dependency>
```

**Or, if you like to leverage auto-configuration:**

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>xsuaa-spring-boot-starter</artifactId>
    <version>2.4.2-SNAPSHOT</version>
</dependency>
```

### Auto-configuration
As auto-configuration requires Spring Boot specific dependencies, it is enabled when using `xsuaa-spring-boot-starter` Spring Boot Starter. 
Then, xsuaa integration libraries auto-configures beans, that are required to initialize the Spring Boot application as OAuth resource server.

Auto-configuration class | Description
---- | --------
[XsuaaAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaAutoConfiguration.java) | Adds `xsuaa.*` properties to Spring's Environment. The properties are by default parsed from `VCAP_SERVICES` system environment variables and can be overwritten by properties such as `xsuaa.xsappname` e.g. for testing purposes. Furthermore it exposes a `XsuaaServiceConfiguration` bean that can be used to access xsuaa service information.  Alternatively you can access them with `@Value` annotation e.g. `@Value("${xsuaa.xsappname:}") String appId`.
[XsuaaResourceServerJwkAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaResourceServerJwkAutoConfiguration.java) | Configures a `JwtDecoder` bean with a JWK (JSON Web Keys) endpoint from where to download the tenant (subdomain) specific public key.

You can gradually replace auto-configurations as explained [here](https://docs.spring.io/spring-boot/docs/current/reference/html/using-boot-auto-configuration.html).


### Setup Security Context for HTTP requests
Configure the OAuth resource server

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
    @Autowired
    XsuaaServiceConfiguration xsuaaServiceConfiguration;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
            .authorizeRequests()
            .antMatchers("/hello-token/**").hasAuthority("Read") // checks whether it has scope "<xsappId>.Read"
            .antMatchers("/actuator/**").authenticated()
            .anyRequest().denyAll()
        .and()
            .oauth2ResourceServer()
            .jwt()
            .jwtAuthenticationConverter(getJwtAuthoritiesConverter());
        // @formatter:on
    }

    Converter<Jwt, AbstractAuthenticationToken> getJwtAuthoritiesConverter() {
        TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
        converter.setLocalScopeAsAuthorities(true);
        return converter;
    }

}
```


### Setup Security Context for non-HTTP requests
In case of non-HTTP requests, you may need to initialize the Spring Security Context with a JWT token you've received from a message / event or you've requested from XSUAA directly:

```java
@Autowired 
XsuaaServiceConfiguration xsuaaServiceConfiguration;

@Autowired
JwtDecoder jwtDecoder;

public void onEvent(String myEncodedJwtToken) {
    if (myEncodedJwtToken != null) {
        SpringSecurityContext.init(myEncodedJwtToken, jwtDecoder, new LocalAuthoritiesExtractor(xsuaaServiceConfiguration.getAppId()));
    }
    try {
        handleEvent();
    } finally {
        SpringSecurityContext.clear();
    }
}
```

In detail `com.sap.cloud.security.xsuaa.token.SpringSecurityContext` wraps the Spring Security Context (namely `SecurityContextHolder.getContext()`), which stores by default the information in `ThreadLocal`s. In order to avoid memory leaks it is recommended to remove the current thread's value for garbage collection.

Note that Spring Security Context is thread-bound and is NOT propagated to child-threads. This [Baeldung tutorial: Spring Security Context Propagation article](https://www.baeldung.com/spring-security-async-principal-propagation) provides more information on how to propagate the context.

## Usage

### Access user/token information
In the Java coding, use the `Token` to extract user information:

```java
@GetMapping("/getGivenName")
public String getGivenName(@AuthenticationPrincipal Token token) {
    return token.getGivenName();
}
```

Or alternatively:
```java
public String getGivenName() {
    Token token = SpringSecurityContext.getToken();
    return token.getGivenName();
}
```

> Note: make sure that you've imported the right Token: `com.sap.cloud.security.xsuaa.token.Token`.


### Check authorization within a method

```java
@GetMapping(@AuthenticationPrincipal Token token)
public ResponseEntity<YourDto> readAll() {
    if (!token.getAuthorities().contains(new SimpleGrantedAuthority("Display"))) {
        throw new NotAuthorizedException("This operation requires \"Display\" scope");
    }
}

...

@ResponseStatus(HttpStatus.FORBIDDEN) //set status code to '403'
class NotAuthorizedException extends RuntimeException {
    public NotAuthorizedException(String message) {
        super(message);
    }
}
```

### Check authorization on method level
Spring Security supports authorization semantics at the method level. As prerequisite you need to enable global Method Security as explained in [Baeldung tutorial: Introduction to Spring Method Security](https://www.baeldung.com/spring-security-method-security).

```java
@GetMapping("/hello-token")
@PreAuthorize("hasAuthority('Display')")
public Map<String, String> message() {
    ...
}
```

## Troubleshoot

- Compile error when upgrading from version `1.5.0` to `1.6.0`:  
  ```
  java.lang.IllegalStateException: Failed to load ApplicationContext
     Caused by: org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'springSecurityFilterChain' defined in class path resource [org/springframework/security/config/annotation/web/configuration/WebSecurityConfiguration.class]: Bean instantiation via factory method failed; nested exception is org.springframework.beans.BeanInstantiationException: Failed to instantiate [javax.servlet.Filter]: Factory method 'springSecurityFilterChain' threw exception; nested exception is org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type 'org.springframework.security.oauth2.jwt.JwtDecoder' available
   ```  
   As of version `1.6.0` you need to make use of XSUAA Spring Boot Starter in order to leverage auto-configuration.
   Make use of the Xsuaa Spring Boot Starter dependency as explained [here](README.md#maven-dependencies).     

