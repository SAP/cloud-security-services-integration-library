# XSUAA Security 

## Integrate in a OAuth resource server

This library enhances the [spring-security](https://github.com/spring-projects/spring-security/) project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. A Spring boot application needs a security configuration class that enables the resource server and configures authentication using JWT tokens.

## Configuration

### Maven Dependencies
```xml
<dependency>
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
    <version>1.6.0</version>
</dependency>
<dependency> <!-- new with version 1.5.0 - provided with org.springframework.boot:spring-boot-starter:jar -->
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-autoconfigure</artifactId> <!--
</dependency>
<dependency> <!-- new with version 1.5.0 - provided with org.springframework.boot:spring-boot-starter:jar -->
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-to-slf4j</artifactId>
    <version>2.11.2</version>
</dependency>
```

### Auto-configuration
The Xsuaa integration libraries auto-configures beans, that are required to initialize the Spring Boot application as OAuth resource server.

Auto-configuration class | Description
---- | --------
XsuaaAutoConfiguration | Adds `xsuaa.*` properties to Spring's Environment. The properties are by default parsed from `VCAP_SERVICES` system environment variables and can be overwritten by properties such as `xsuaa.xsappname` e.g. for testing purposes. Furthermore it exposes a `XsuaaServiceConfiguration` bean that can be used to access xsuaa service information.  Alternatively you can access them with `@Value` annotation e.g. `@Value("${xsuaa.xsappname:}") String appId`.
XsuaaResourceServerJwkAutoConfiguration | Configures a `JwtDecoder` bean with a JWK (JSON Web Keys) endpoint from where to download the tenant (subdomain) specific public key.

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
In case of non-HTTP requests, you may need to initialize the Spring `SecurityContext` with a JWT token you've received from a message / event or you've requested from XSUAA directly:

```java
@Autowired
JwtDecoder jwtDecoder;

@Value("${xsuaa.xsappname}")
String xsappname;

public void onEvent(String myEncodedJwtToken) {
    Jwt jwtToken = jwtDecoder.decode(myEncodedJwtToken);
    SecurityContext.init(xsappname, myEncodedJwtToken, true);
    try {
        // ... handle event
    } finally {
        SecurityContext.clear();
    }
}
```

In detail `com.sap.xs2.security.container.SecurityContext` wraps the Spring `SecurityContext`, which stores by default the information in `ThreadLocal`s. In order to avoid memory leaks it is recommended to remove the current thread's value for garbage collection.

Note that Spring `SecurityContext` is thread-bound and is NOT propagated to child-threads. This [Baeldung tutorial: Spring Security Context Propagation article](https://www.baeldung.com/spring-security-async-principal-propagation) provides more information on how to propagate the context.

## Usage

### Access user/token information
In the Java coding, use the `Token` to extract user information:

```java
@GetMapping("/hello-token")
public Map<String, String> message(@AuthenticationPrincipal Token token) {
    token.getGivenName();
}
```

Or alternatively:
```java
public Map<String, String> message() {
    Token token = SecurityContext.getToken();
    token.getGivenName();
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

