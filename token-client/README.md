# XSUAA Token Client and Token Flow API

## Motivation

This library serves as slim client for some XSUAA `/oauth/token` token endpoints as specified [here](https://docs.cloudfoundry.org/api/uaa/version/74.1.0/index.html#token). 
Furthermore it introduces a new API to support the following token flows:

* **User Token Flow**.  
The idea behind a User Token exchange is to separate service-specific access scopes into separate tokens. For example, if Service A has scopes specific to its functionality and Service B has other scopes, the intention is that there is no single Jwt token that contains all of these scopes. As of version `2.5.1` the `grant_type`=`urn:ietf:params:oauth:grant-type:jwt-bearer` is used ([RFC 7523](https://tools.ietf.org/html/rfc7523)).
* **Client Credentials Flow**.  
The Client Credentials ([RFC 6749, section 4.4](https://tools.ietf.org/html/rfc6749#section-4.4)) is used by clients to obtain an access token outside of the context of a user. It is used for non interactive applications (a CLI, a batch job, or for service-2-service communication) where the token is issued to the application itself, instead of an end user for accessing resources without principal propagation. 
* **Refresh Token Flow**.  
A Refresh Token ([RFC 6749, section 1.5](https://tools.ietf.org/html/rfc6749#section-1.5)) flow allows you to obtain a new access token in case the current one becomes invalid or expires.
* **Password Token Flow**.  
The Resource owner password credentials (i.e., username and password) can be used directly as an authorization grant to obtain an access token ([RFC 6749, section 1.3.3](https://tools.ietf.org/html/rfc6749#section-1.3.3)). The credentials should only be used when there is a high degree of trust between the resource owner and the client.

> Note: The **Authorization Code Grant Flow** involves the browser and is therefore triggered by an API gateway (e.g. Application Router). The other flows, however, may need to be triggered programmatically, e.g. to exchange one token for another or refresh a token, if it is about to expire. When you create a XSUAA service instance a OAuth client gets created and you receive the client credentials (client id and secret) when you bind your application with the XSUAA service instance. Having that in place you are ready to use the token flows in your Java application.

## Configuration for Java Applications

#### Maven Dependencies, when using Apache Http Client:
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client</artifactId>
    <version>2.6.0</version>
</dependency>
<dependency>
  <groupId>org.apache.httpcomponents</groupId>
  <artifactId>httpclient</artifactId>
</dependency>
```

#### Initialization
Instantiate `XsuaaTokenFlows` with the `DefaultOAuth2TokenService` which
makes use of [Apache HttpClient](https://hc.apache.org/):

```java
XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
                                    new DefaultOAuth2TokenService(), 
                                    new XsuaaDefaultEndpoints(<uaa_base_url>), 
                                    new ClientCredentials(<client_id>, <client_secret>));
```
The `DefaultOAuth2TokenService` can also be instantiated with a custom `CloseableHttpClient`.

> The `<uaa_base_url>`, `<client_id>` and `<client_secret>` are placeholders for the information you get from the XSUAA service binding. 


## Configuration for Java/Spring Applications

#### Maven Dependencies, when using Spring Web `RestTemplate`
```xml
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-web</artifactId>
</dependency>
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client</artifactId>
    <version>2.6.0</version>
</dependency>
```

#### Initialization

With Spring-Web available `XsuaaTokenFlows` can be instantiated with a `RestTemplate` of your choice like that:
```java
XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
                                    new XsuaaOAuth2TokenService(new RestTemplate()),
                                    new XsuaaDefaultEndpoints(<uaa_base_url>),
                                    new ClientCredentials(<client_id>, <client_secret>));
```
> The `<uaa_base_url>`, `<client_id>` and `<client_secret>` are placeholders for the information you get from the XSUAA service binding. In case you leverage the spring-xsuaa library you can also use [`XsuaaServiceConfiguration`](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/XsuaaServiceConfiguration.java) class.

## Configuration for Spring Boot Applications

#### Maven Dependencies
In context of a Spring Boot application you may like to leverage auto-configuration:
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>xsuaa-spring-boot-starter</artifactId>
    <version>2.6.0</version>
</dependency>
```

#### Auto-configuration
As auto-configuration requires Spring Boot specific dependencies, it is enabled when using `xsuaa-spring-boot-starter` Spring Boot Starter. 
Then, xsuaa integration libraries auto-configures beans, that are required to initialize the Token Flows API.

Auto-configuration class | Description
---- | --------
[XsuaaAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaAutoConfiguration.java) | Adds `xsuaa.*` properties to Spring's Environment. The properties are by default parsed from `VCAP_SERVICES` system environment variables and can be overwritten by properties such as `xsuaa.url` e.g. for testing purposes. Furthermore it exposes a `XsuaaServiceConfiguration` bean that can be used to access xsuaa service information.  Alternatively you can access them with `@Value` annotation e.g. `@Value("${xsuaa.url:}") String xsuaaBaseUrl`. As of version `1.7.0` it creates a default [`RestTemplate`](https://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/client/RestOperations.html) bean that serves as Rest client that is used inside a default `OAuth2TokenService` to perform HTTP requests to the XSUAA server. **It is recommended to overwrite this default and configuring it with the HTTP client of your choice.**
[XsuaaTokenFlowAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaTokenFlowAutoConfiguration.java) | Configures a `XsuaaTokenFlows` bean for a given `RestOperations` and `XsuaaServiceConfiguration` bean to fetch the XSUAA service binding information.

You can gradually replace auto-configurations as explained [here](https://docs.spring.io/spring-boot/docs/current/reference/html/using-boot-auto-configuration.html).

#### Initialization
To consume the `XsuaaTokenFlows` class, you simply need to `@Autowire` it like this:

```java
@Autowired
private XsuaaTokenFlows xsuaaTokenFlows;
```

## Usage
The `XsuaaTokenFlows` provides a builder-pattern API that allows applications to easily create and execute each flow, guiding developers to only set properties that are relevant for the respective token flow.


### Client Credentials Token Flow
Obtain a client credentials token:

```java
OAuth2TokenResponse clientCredentialsToken = tokenFlows.clientCredentialsTokenFlow()
                                                    .subdomain(jwtToken.getSubdomain()) // this is optional 
                                                    .execute();
```
### Refresh Token Flow
In case you have a refresh token and want to obtain an access token:

```java
OAuth2TokenResponse refreshToken = tokenFlows.refreshTokenFlow()
                              .refreshToken(<refresh_token>)
                              .subdomain(jwtToken.getSubdomain()) // this is optional 
                              .execute();
```
### User Token Flow
In order to exchange a user token for another user access token:
```java
XsuaaToken jwtToken = SpringSecurityContext.getToken();

OAuth2TokenResponse userToken = tokenFlows.userTokenFlow()
                .token(jwtToken)
                .subdomain(jwtToken.getSubdomain()) // this is optional      
                .attributes(additionalAttributes) // this is optional
                .execute();
```


### Password Token Flow
In order to obtain an access token for a user:
```java
OAuth2TokenResponse clientCredentialsToken = tokenFlows.passwordTokenFlow()
                                                    .subdomain(jwtToken.getSubdomain()) // this is optional
                                                    .username(<your username>)
                                                    .password(<your password>)
                                                    .execute();
```


Make sure to read the API documentation of the `XsuaaTokenFlows` API, to understand what the individual token flows' parameters are for.


## Samples
- [Java sample](/samples/java-tokenclient-usage)
- [Spring Boot sample](/samples/spring-security-xsuaa-usage)
