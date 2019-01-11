# XSUAA Security 

## Integrate in a OAuth resource server

This library enhances the [spring-security](https://github.com/spring-projects/spring-security/) project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. A Spring boot application needs a security configuration class that enables the resource server and configures authentication using JWT tokens.

## Setup
Set the property source for xsuaa service binding on the application:

```java
@SpringBootApplication
@ComponentScan
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    XsuaaServiceConfigurationDefault xsuaaDefaultConfig() {
        return new XsuaaServiceConfigurationDefault();
    }
}
```

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
        http.authorizeRequests()
            .antMatchers("/hello-token/**").hasAuthority("Read") // checks whether it has scope "<xsappId>.Read"
            .antMatchers("/actuator/**").authenticated()
            .anyRequest().denyAll()
        .and()
            .oauth2ResourceServer()
            .jwt()
            .decoder(jwtDecoder())
            .jwtAuthenticationConverter(jwtAuthenticationConverter());
        // @formatter:on
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration).build();
    }

    @Bean
    Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        return new TokenAuthenticationConverter(xsuaaServiceConfiguration);
    }
}
```

> Note: with `XsuaaServicePropertySourceFactory` the VCAP_SERVICES properties are read from the system environment variable and mapped to properties such as `xsuaa.xsappname`.
> You can access them via Spring `@Value` annotation e.g. `@Value("${xsuaa.xsappname:}") String appId`.
> For testing purposes you can overwrite them, for example, as part of a *.properties file.

## Usage

### Check authorization on method level

```java
@GetMapping("/hello-token")
@PreAuthorize("hasAuthority('Display')
public Map<String, String> message() {
    ...
}
```

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


