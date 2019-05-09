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
    <version>1.2.0</version>
</dependency>
```


### Setup Security Context for HTTP requests
Configure the OAuth resource server

```java
@Configuration
@EnableWebSecurity
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = {""})
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
    @Autowired
    XsuaaServiceConfigurationDefault xsuaaServiceConfiguration;

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

    @Bean
    JwtDecoder jwtDecoder() {
        return new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration).build();
    }

    @Bean
    XsuaaServiceConfigurationDefault xsuaaConfig() {
        return new XsuaaServiceConfigurationDefault();
    }
}
```

> Note: with `XsuaaServicePropertySourceFactory` the VCAP_SERVICES properties are read from the system environment variable and mapped to properties such as `xsuaa.xsappname`.
> You can access them via Spring `@Value` annotation e.g. `@Value("${xsuaa.xsappname:}") String appId`.
> For testing purposes you can overwrite them, for example, as part of a *.properties file.

### Setup Security Context for non-HTTP requests
In case of non-HTTP requests, you may need to initialize the Spring `SecurityContext` with a JWT token you've received from a message / event or you've requested from XSUAA directly.

Configure the `JwtDecoder` bean using the `XsuaaJwtDecoderBuilder` class

```
@Configuration
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = {""})
public class SecurityConfiguration {

    @Autowired
    XsuaaServiceConfigurationDefault xsuaaServiceConfiguration;

    @Bean
    JwtDecoder jwtDecoder() {
        return new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration).build();
    }

    @Bean
    XsuaaServiceConfigurationDefault xsuaaConfig() {
        return new XsuaaServiceConfigurationDefault();
    }
}
```

Then, initialize the `SecurityContext`
```
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

