# XSUAA Security 

   * [Integration with Spring Security OAuth 2.0 Resource Server](#integration-with-spring-security-oauth-20-resource-server)
   * [Configuration](#configuration)
      * [Maven Dependencies](#maven-dependencies)
      * [Setup Security Context for HTTP requests](#setup-security-context-for-http-requests)
      * [Advanced Security Configurations](#advanced-security-configurations)
         * [Exchanging the Standard JWT Implementation](#exchanging-the-standard-jwt-implementation)
         * [Simplifying Token Scope Names](#simplifying-token-scope-names)
         * [Reference Of Configuration Options](#reference-of-configuration-options)
         * [Setup Security Context for non-HTTP requests](#setup-security-context-for-non-http-requests)
      * [Usage](#usage)
         * [Exchanging Tokens with XsuaaTokenFlows](#exchanging-tokens-with-xsuaatokenflows)
         * [Accessing XSUAA Binding Information using XsuaaServiceBindings](#accessing-xsuaa-binding-information-using-xsuaaservicebindings)
         * [Programmatically Checking Authorities](#programmatically-checking-authorities)
         * [Authorization Checks Using Global Method Security](#authorization-checks-using-global-method-security)
         * [Auto-Configuration](#auto-configuration)

# Integration with Spring Security OAuth 2.0 Resource Server

This library integrates with the [spring-security](https://github.com/spring-projects/spring-security/) project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. A Spring Boot application using Spring Security OAuth 2.0 uses a security configuration that enables the resource server and configures authentication using JWT tokens. This configuration is partially done in a Java class (usually called `WebSecurityConfigurations`) and in the application's `application.yml`.

In the following we will describe how to integrate `spring-xsuaa` into your application.

# Configuration

## Maven Dependencies

A typical `pom.xml` for an application that intregrates `spring-xsuaa` looks as follows.

```xml
<?xml version="1.0"?>
<project
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd"
    xmlns="http://maven.apache.org/POM/4.0.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.1.4.RELEASE</version>
        <relativePath />
    </parent>

    <groupId>com.sap.cloud.security.samples</groupId>
    <artifactId>spring-security-xsuaa-usage</artifactId>
    <version>2.0.0</version>
    <name>spring-security-xsuaa-usage</name>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
        <java.version>1.8</java.version>
    </properties>

    <dependencies>
	
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
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
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-oauth2-jose</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-jwt</artifactId>
        <version>1.0.10.RELEASE</version>
    </dependency>

    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-oauth2-resource-server</artifactId>
    </dependency>

    <dependency>
        <groupId>com.sap.cloud.security.xsuaa</groupId>
        <artifactId>spring-xsuaa</artifactId>
        <version>2.0.0</version>
    </dependency>

    </dependencies>

    <build>
        <finalName>${project.artifactId}</finalName>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

Notice the `spring-xsuaa` library reference at the bottom. The other libraries are pre-requisites of 
`spring-xsuaa` (and in the future should be made available as a maven BOM).

## Setup Security Context for HTTP requests

Configure the OAuth resource server

In `application.yml` make sure to have the following (landscape-specific) configuration:

```yml
---
spring:
  # Spring Security Configurations Pointing to XSUAA
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: https://authentication.eu10.hana.ondemand.com/token_keys
```

In this snippet, we are configuring the publicly available XSUAA server on the AWS EU10 landscape.
For internal, canary landscapes the domain of the URL may differ.

That little bit of configuration is actually enough to get you started. It will configure your application to be an OAuth 2.0 resource server, that will validate tokens based on the public keys found by the `jwk-set-uri` configured above. Since `spring-xsuaa` auto-configures itself when Spring Security OAuth 2.0 is on the classpath, a JWT's audience will also be validated automatically.

Most likely, however, you will want to control, which endpoints of your application should be protected by JWT tokens.
You do so by creating a `WebSecurityConfiguration` class like this one:

```java
@EnableWebSecurity(debug = true)
public class WebSecurityConfigurations extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/health").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_<scope from JWT>") 
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt();
        // @formatter:on
    }
}
```

With this minimal configuration, you can allow access to the `/actuator/health` endpoint, and enforce that access to `/v1/address` is only allowed if 
1. there is a JWT token, and that 
2. the the respective scope is given in the JWT token.

This is the simplest configuration that you can use. In the next section we present a little more advanced configurations.

## Advanced Security Configurations

The simple configurations shown above do the job, but as you will find out, working with XSUAA scopes is not much fun, as they are prefixed at runtime with information an application may find cumbersome.  
Here we present different configuration options that you might find useful.

Most notably, they differ in the way an application consumes a Jwt token, i.e. which implementation of the Jwt, and how the scopes inside the token are exposed.

### Exchanging the Standard JWT Implementation
Basically, it is possible in Spring Security to exchange the framework's JWT token implementation under the hood.
By default Spring Security uses `org.springframework.security.oauth2.jwt.Jwt` as its JWT token implementation class. Typically, this is what applications using Spring Security OAuth 2.0 are used to. 

However, since XSUAA also adds some custom claims to the standard JWT token, we also provide `com.sap.cloud.security.xsuaa.XsuaaToken` as a possible implementation. You can use this class either as a simple wrapper to a standard `org.springframework.security.oauth2.jwt.Jwt`, or as a replacement.

In a wrapper approach, an application would simply consume the Jwt like this:

```java
@RequestMapping(value = "/v1/address", method = RequestMethod.GET)
public String sayHello(@AuthenticationPrincipal Jwt jwt) throws Exception {
    logger.info("Got the standard JWT: " + jwt);
    
    // You can always use the XSUAAToken as a wrapper.
    XsuaaToken token = new XsuaaToken(jwt);
    
    logger.info(token.toString());
           
    return "Hello Jwt-Protected World!";
}
```

In case you wanted to exchange Spring Security's JWT implementation, all you need to do is use the following configuration:

```java
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfigurations extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        configure_ExchangingStandardJwtForXSUAAToken(http);
    }
     
    private void configure_ExchangingStandardJwtForXSUAAToken(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource")
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt()
                       .jwtAuthenticationConverter(jwtToXsuaaTokenConverter());
        // @formatter:on 
    }
    
    Converter<Jwt, AbstractAuthenticationToken> jwtToXsuaaTokenConverter() {
        return new XsuaaTokenConverter();
    }
}
```

With this configuration, your application can consume the XSUAA-issued token like this:

```java
@RequestMapping(value = "/v1/address", method = RequestMethod.GET)
public String sayHello(@AuthenticationPrincipal XsuaaToken token) throws Exception {
    logger.info("Got the customized XSUAA Token: {}", token);
    logger.info("Token subdomain (custom field) is: {}", token.getSubdomain()); //won't find that on a standard Jwt!
    return "Hello Jwt-Protected World!";
}
```

`XsuaaToken` inherits from `org.springframework.security.oauth2.jwt.Jwt` so basically, you still have all the usual accessor methods but some added convenience, if you'd like to.

### Simplifying Token Scope Names

Spring Security OAuth 2.0 converts JWT scopes into so-called `GrantedAuthority` objects. These `GrantedAuthority` objects are subsequently what an application validates / checks. They are used in `WebSecurityConfiguration` when you use the `hasScope(...)` method just as well as in Spring Expression Language (SpEL) when you check scopes in method annotations using Spring Global Method Security.

Usually, an `GrantedAuthority` in Spring Security starts with `SCOPE_` followed by the respective scope from a JWT, e.g. `SCOPE_read`, etc.
Unfortunately, XSUAA's scopes look a little cumbersome, typically including the XS App Name as a prefix to the actual scope itself. The result usually looks similar to this: `<someAppName>!t1245.read` or `sb-<instanceId>!b<number>|<someAppName>!b<number>.read`. You can of course check for that scope in your application, but chances are you don't.

We have added some support to cut XSUAA scopes in the JWT to nicer names. If your application or service does not need the prefix at all (e.g. because you are sure that the scopes you will receive are all intended for your app only), you can choose to easily remove the prefix by the following configuration:

```java
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfigurations extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        configure_UsingStandardJWT_And_NicerAuthorityNames(http);
    }
     
    private void configure_UsingStandardJWT_And_NicerAuthorityNames(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource") // made possible by the xsAppNameReplacingAuthoritiesExtractor() that was added using .jwtAuthenticationConverter().
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt()
                        .jwtAuthenticationConverter(xsAppNameReplacingAuthoritiesExtractor());
        // @formatter:on 
    }
    
    Converter<Jwt, AbstractAuthenticationToken> xsAppNameReplacingAuthoritiesExtractor() {
        return new XsAppNameReplacingAuthoritiesExtractor();
    }   
}
```

Note, how an instance of `XsAppNameReplacingAuthoritiesExtractor` can be used to simply cut off the prefix based on a regular expression pattern.

In case you did not want to cut off the prefix entirely, but map it to something more human-readable, you can also pass in a `java.util.Map` instance to `XsAppNameReplacingAuthoritiesExtractor(Map<String, String>)`. That will replace any occurrence added as a key with the value in the map.

Of course, you can also use this mechanism, if you are replacing the standard `Jwt` with the `XsuaaToken` implementation. See next section for reference.

### Reference Of Configuration Options

Below you can find all 4 options (standard & custom JWT with and without nicer authority names) for reference.
Note, that this configuration also configures Spring Security's **Global Method Security**. This allows your application to also annotate methods with authority checks. See the `spring-security-xsuaa-usage` sample's [`DataLayer`](../samples/spring-security-xsuaa-usage/src/main/java/sample/spring/xsuaa/datalayer/DataLayer.java) interface for an example.

```java
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfigurations extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Pick either of these to try things out.
        //configure_ExchangingStandardJwtForXSUAAToken(http);
        configure_ExchangingStandardJwtForXSUAAToken_And_NicerAuthorityNames(http);
        //configure_UsingStandardJWT_And_NicerAuthorityNames(http);
        //configure_UsingStandardJWT(http);
    }
     
    /**
     * Configures Spring Security to exchange the standard Jwt for a custom XSUAAToken implementation.
     * This allows you to reference the XSUAAToken in REST controller methods using 
     * {@code @AuthenticationPrincipal XSUAAToken token}. I.e. you do not have to cast tokens.
     * You can, however, also still use {@code @AuthenticationPrincipal Jwt jwt} since XSUAAToken is a
     * direct descendant of Spring's Jwt class.  
     * 
     * Scopes will be mapped to authorities in the standard Spring Security way. No modification
     * of scope names is performed (except for Spring Securities addition of the SCOPE_ prefix).
     * 
     * @param http
     * @throws Exception
     */
    private void configure_ExchangingStandardJwtForXSUAAToken(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource")
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt()
                       .jwtAuthenticationConverter(jwtToXsuaaTokenConverter());
                     // .decoder(decoder)                                             // see: https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2resourceserver-decoder-dsl
                     // .jwkSetUri(uri)                                               // see: https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2resourceserver-jwkseturi-dsl
                     // .jwtAuthenticationConverter(getJwtAuthenticationConverter()); // see: https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2resourceserver-authorization-extraction
        // @formatter:on 
    }
    
    /**
     * Configures Spring Security to exchange the standard Jwt for a custom XSUAAToken implementation.
     * This allows you to reference the XSUAAToken in REST controller methods using 
     * {@code @AuthenticationPrincipal XSUAAToken token}. I.e. you do not have to cast tokens.
     * You can, however, also still use {@code @AuthenticationPrincipal Jwt jwt} since XSUAAToken is a
     * direct descendant of Spring's Jwt class.
     * 
     * Scopes will be mapped to authorities in a custom way replacing the XsAppName in the scopes for empty
     * strings. This allows checking a scope of {@code spring-netflix-demo!t12291.Read} simply by calling
     * {@code hasAuthority("SCOPE_Read")}.
     * 
     * Note that replacing the XsAppName can be customized so, you could add your own replacement string 
     * (other than the empty string) for it.
     * 
     * @param http
     * @throws Exception
     */
    private void configure_ExchangingStandardJwtForXSUAAToken_And_NicerAuthorityNames(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource") // made possible by the jwtToXsuaaTokenConverterReplacingXSAppName() that was added using .jwtAuthenticationConverter().
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt()
                        .jwtAuthenticationConverter(jwtToXsuaaTokenConverterReplacingXSAppName());
        // @formatter:on 
    }
    
    /**
     * Configures Spring Security to use the standard Spring Security Jwt implementation, but maps the
     * Jwt's authorities in a custom way replacing the XsAppName in the scopes for empty
     * strings. This allows checking a scope of {@code spring-netflix-demo!t12291.Read} simply by calling
     * {@code hasAuthority("SCOPE_Read")}.
     * 
     * Note that replacing the XsAppName can be customized so, you could add your own replacement string 
     * (other than the empty string) for it.
     * 
     * You will be able to refer to the Jwt in REST controllers only by {@code @AuthenticationPrincipal Jwt jwt}
     * not {@code @AuthenticationPrincipal XSUAAToken token}. The latter will throw a runtime cast exception.
     * 
     * @param http
     * @throws Exception
     */
    private void configure_UsingStandardJWT_And_NicerAuthorityNames(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource") // made possible by the xsAppNameReplacingAuthoritiesExtractor() that was added using .jwtAuthenticationConverter().
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt()
                        .jwtAuthenticationConverter(xsAppNameReplacingAuthoritiesExtractor());
        // @formatter:on 
    }
    
    /**
     * Configures Spring Security to use the standard Spring Security Jwt as it comes out of the box.
     * No scope / authority adaptations are performed other than the default Spring Security ones (i.e.
     * adding the SCOPE_ prefix).
     * 
     * You will be able to refer to the Jwt in REST controllers only by {@code @AuthenticationPrincipal Jwt jwt}
     * not {@code @AuthenticationPrincipal XSUAAToken token}. The latter will throw a runtime cast exception.
     * 
     * @param http
     * @throws Exception
     */
    private void configure_UsingStandardJWT(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource") // made possible by the xsAppNameReplacingAuthoritiesExtractor() that was added using .jwtAuthenticationConverter().
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt();
        // @formatter:on 
    }
    
    /**
     * A JWT token's scopes are by default converted into Spring Security Authorities and prefixed with "SCOPE_".
     * You can then use these authorities in Spring Security Expression Language (SpEL) terms or 
     * in the .hasAuthority(...) methods of the WebSecurityConfigurationAdapter.
     * 
     * You can also override the default mapping like this.
     * It basically extracts the scopes from the JWT and strips the XSUAA XSAPPNAME and tenant host pattern.
     * As a result you can just use ".hasAuthority("SCOPE_Read")" rather than "hasAuthority("SCOPE_spring-netflix-demo!t12291.Read")"
     * @return the authorities extractor used to map / extract JWT scopes.
     */
    Converter<Jwt, AbstractAuthenticationToken> xsAppNameReplacingAuthoritiesExtractor() {
        return new XsAppNameReplacingAuthoritiesExtractor();
    }
    
    
    /**
     * Converts a Jwt token from Spring Security to an XSUAA token.
     * 
     * Our XSUAA token inherits from Jwt, so applications don't lose any
     * standard Jwt functionality, but gain some more convenience.
     * In REST endpoints you can use {@code @AuthenticationPrincipal Jwt jwt}
     * or {@code @AuthenticationPrincipal XSUAAToken token} interchangeably.
     * @return the token converter.
     */
    Converter<Jwt, AbstractAuthenticationToken> jwtToXsuaaTokenConverter() {
        return new XsuaaTokenConverter();
    } 
    
    /**
     * Converts a Jwt token from Spring Security to an XSUAA token.
     * Also replaces the XSAppName in the scopes when mapping them to 
     * granted authorities.
     * 
     * Our XSUAA token inherits from Jwt, so applications don't lose any
     * standard Jwt functionality, but gain some more convenience.
     * In REST endpoints you can use {@code @AuthenticationPrincipal Jwt jwt}
     * or {@code @AuthenticationPrincipal XSUAAToken token} interchangeably.
     * @return the token converter.
     */
    Converter<Jwt, AbstractAuthenticationToken> jwtToXsuaaTokenConverterReplacingXSAppName() {
        return new XsuaaTokenConverter(new XsAppNameReplacingAuthoritiesExtractor());
    }   
}
```

### Setup Security Context for non-HTTP requests

In case of non-HTTP requests (e.g. an Event from an event bus), you may need to initialize the Spring `SecurityContext` with a JWT token you've received from a message / event or you've requested from XSUAA directly.

Then, initialize the `SecurityContext`

```java
@Autowired
JwtDecoder jwtDecoder;

@Autowired
XsuaaServiceBindings xsuaaServiceBindings;

public void onEvent(String encodedJwtTokenValue) {
    Jwt jwtToken = jwtDecoder.decode(encodedJwtTokenValue);
    SecurityContext.init(xsuaaServiceBindings.getCredentials().getXsAppName(), encodedJwtTokenValue, true);
    try {
        // ... handle event
    } finally {
        SecurityContext.clear();
    }
}
```

Note that Spring `SecurityContext` is thread-bound and is NOT propagated to child-threads unless explicitly stated, using the following line:
```java
SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
```

See also [Spring Security Context Propagation](https://www.baeldung.com/spring-security-async-principal-propagation) for more information.

## Usage

### Exchanging Tokens with `XsuaaTokenFlows`

XSUAA supports the following token flows:

* Authorization Code Grant
* User Token Grant
* Client Credentials Token Grant
* Refresh Token Grant

Authorization Code Grant is a flow that involves the browser and is therefore triggered by an API gateway (e.g. AppRouter). The other flows, however, may need to be triggered programmatically, e.g. to exchange one token for another or refresh a token, if it is about to expire.

To that end, we provide the `XsuaaTokenFlows` class, which serves as a factory for the different flows. 

The flows themselves provide a builder-pattern API that allows applications to easily create and execute each flow.

To consume the `XsuaaTokenFlows` class, you simply need to `@Autowire` it like this:
```java
@Autowired
private XsuaaTokenFlows xsuaaTokenFlows;
```

Then, you can create e.g. a client credentials token flow very easily by the following code:

```java
Jwt ccfToken = xsuaaTokenFlows.clientCredentialsTokenFlow(URI.create(baseUrl))
                .client(clientId)
                .secret(clientSecret)
                .execute();
```
Have a look for the other possible flows and how easily they can be executed.

### Accessing XSUAA Binding Information using `XsuaaServiceBindings`

Sometimes, it may be necessary for an application to access the binding information of bound XSUAA instances from the `VCAP_SERVICES` environment. This can be easily done using the `XsuaaServiceBindings` class.

`XsuaaServiceBindings` supports multiple XSUAA instances that may be bound to your application and allows you distinct access to each binding information by the XSUAA instance **name**.

You can access `XsuaaServiceBindings` simply by `@Autowire`ing it into your application:

```java
@Autowired
private XsuaaServiceBindings xsuaaServiceBindings;
```
usage then is as simple as:

```java
XsuaaBindingInfo xsuaaBindingInfo = xsuaaServiceBindings.get("xsuaa-authentication");
String baseUrl = xsuaaBindingInfo.getCredentials().getBaseUrl();
String clientId = xsuaaBindingInfo.getCredentials().getClientId();
String clientSecret = xsuaaBindingInfo.getCredentials().getClientSecret();
```

`XsuaaServiceBinding` looks for XSUAA binding information in the application's environment at startup and will fail, if the binding information is not present.

To run your application offline and making the binding information available easily, applications can place a file called `vcap-services.json` into their `src/main/resources` folder and simply dump the VCAP_SERVICES contents from Cloud Foundry there like this:

```json
{
    "xsuaa": [
      {
        "label": "xsuaa",
        "provider": null,
        "plan": "application",
        "name": "xsuaa-authentication",
        "tags": [
          "xsuaa"
        ],
        "instance_name": "xsuaa-authentication",
        "binding_name": null,
        "credentials": {
          "tenantmode": "dedicated",
          "sburl": "https://internal-xsuaa.authentication.eu10.hana.ondemand.com",
          "clientid": "YOUR-CLIENT-ID",
          "xsappname": "YOUR-XS-APP-NAME",
          "clientsecret": "YOUR-CLIENT-SECRET",
          "url": "https://YOUR-TENANT.authentication.eu10.hana.ondemand.com",
          "uaadomain": "authentication.eu10.hana.ondemand.com",
          "verificationkey": "-----BEGIN PUBLIC KEY-----...YOUR KEY...-----END PUBLIC KEY-----",
          "apiurl": "https://api.authentication.eu10.hana.ondemand.com",
          "identityzone": "YOUR-TENANT",
          "identityzoneid": "d22b9a7f-53b2-4f88-8298-cc51f86e7f68",
          "tenantid": "d22b9a7f-53b2-4f88-8298-cc51f86e7f68"
        },
        "syslog_drain_url": null,
        "volume_mounts": []
      },
      {
        "label": "xsuaa",
        "provider": null,
        "plan": "application",
        "name": "another-xsuaa-instance",
        "tags": [
          "xsuaa"
        ],
        "instance_name": "another-xsuaa-instance",
        "binding_name": null,
        "credentials": {
          "uaadomain": "authentication.eu10.hana.ondemand.com",
          "tenantmode": "shared",
          "sburl": "https://internal-xsuaa.authentication.eu10.hana.ondemand.com",
          "clientid": "YOUR-CLIENT-ID",
          "verificationkey": "-----BEGIN PUBLIC KEY-----...YOUR KEY...-----END PUBLIC KEY-----",
          "xsappname": "YOUR-XS-APP-NAME",
          "identityzone": "YOUR-TENANT",
          "identityzoneid": "d22b9a7f-53b2-4f88-8298-cc51f86e7f68",
          "clientsecret": "YOUR-CLIENT-SECRET",
          "tenantid": "d22b9a7f-53b2-4f88-8298-cc51f86e7f68",
          "url": "https://YOUR-TENANT.authentication.eu10.hana.ondemand.com"
        },
        "syslog_drain_url": null,
        "volume_mounts": []
      }
    ]
}
```

### Programmatically Checking Authorities

Usually, authorities are checked declaratively (either using `hasScope(...)` in `WebSecurityConfiguration` or using Global Method Security annotations). However, in case you really need to access the scopes of the JWT token programmatically, you can do so as follows:

```java
List<String> scopes = jwt.getClaimAsStringList("scope");
if(scopes.contains("theScopeIamLookingFor")) {
    //do something
}
else {
    throw new Exception("Access denied!");
}
```

You can also access the `GrantedAuthorities`, i.e. the converted scopes like this:

```java
Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) SecurityContextHolder.getContext().getAuthentication().getAuthorities();
```
Then you can check if the authority you are looking for is contained in the list.

### Authorization Checks Using Global Method Security 
Spring Security supports authorization semantics at the method level. As prerequisite you need to enable Global Method Security as shown above and explained in [Introduction to Spring Method Security](https://www.baeldung.com/spring-security-method-security).

After that, you can use code like the follwing to check if a token has the required authorities for the method to be called. 

```java
@GetMapping("/hello-token")
@PreAuthorize("hasAuthority('Display')")
public Map<String, String> message() {
    ...
}
```

Note, that Spring Global Method Security is much more powerful than that. It also supports post-authorize checks and filtering. Make sure you familiarize yourself with it. You can also find an example in the `samples/spring-security-xsuaa-usage` project.

### Auto-Configuration

`spring-xsuaa` uses Spring Boot Auto-Configuration to plug itself into the Spring Security OAuth 2.0 environment.
As the name implies, this happens automatically when you reference `spring-xsuaa` from maven, i.e. when the `spring-xsuaa.jar` is on the classpath.

`spring-xsuaa`'s auto-configuration exposes the `XsuaaTokenFlows` and `XsuaaServiceBindings` beans and also a customized `JwtDecoder` instance that also validates a Jwt token's audience against the OAuth `clientId`, `clientSecret` and `XsAppName` that are found in the XSUAA binding information within the environment of the application.

The two auto-configuration classes are `XsuaaResourceServerJwkConfiguration` and `XsuaaDefaultConfigurations`.
They declare all beans with the `@ConditionalOnMissingBean` annotation, which allows an application to expose their own versions and override the `spring-xsuaa` default, if necessary.

With this mechanism, an application has ultimate flexibility while at the same time profiting from meaningful defaults that simply plug in "magically" under the hood.

