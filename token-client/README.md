# XSUAA Token Client and Token Flow API

This library provides a lightweight HTTP client for Xsuaa `/oauth/token` and `/token_keys` endpoints, as specified [here](https://docs.cloudfoundry.org/api/uaa/version/76.9.0/#token). 
Additionally, it offers an API with the [XsuaaTokenFlows](./src/main/java/com/sap/cloud/security/xsuaa/tokenflows/XsuaaTokenFlows.java) class to support the following token flows:

* **[Jwt Bearer Token Flow](#jwt-bearer-token-flow)**.  
  The token exchange concept aims to segregate service-specific access scopes into separate tokens. For instance, if Service A and Service B have different scopes, the goal is to avoid having a single Jwt token containing all scopes. To achieve principal propagation in that scenario, Service A could use a Jwt Bearer Token Flow before making requests to Service B on behalf of the user. To do so, he would exchange the user's access token for Service A for an access token of the same user for Service B.
* **[Client Credentials Flow](#client-credentials-token-flow)**.  
  The Client Credentials ([RFC 6749, section 4.4](https://tools.ietf.org/html/rfc6749#section-4.4)) are employed by clients to acquire an access token without a user context. This is useful for non-interactive applications (e.g., CLI, batch job, or service-2-service communication) where the token is issued to the application itself, instead of an end-user for accessing resources without principal propagation.
* **[Refresh Token Flow](#refresh-token-flow)**.  
  A Refresh Token ([RFC 6749, section 1.5](https://tools.ietf.org/html/rfc6749#section-1.5)) flow enables obtaining a new access token if the current one becomes invalid or expires.
* **[Password Token Flow](#password-token-flow)**.  
  Resource owner password credentials (i.e., username and password) can be used directly as an authorization grant to obtain an access token ([RFC 6749, section 1.3.3](https://tools.ietf.org/html/rfc6749#section-1.3.3)). These credentials should be employed only when there is a high degree of trust between the resource owner and the client.

> Note: The **Authorization Code Grant Flow** requires a browser and is typically initiated by an API gateway, such as an Application Router. However, other flows might need to be triggered programmatically, such as swapping one token for another or refreshing a token prior to its expiration. When creating an Xsuaa service instance, an OAuth client is generated, and the client Identity (client ID and secret or client certificate and key) are supplied when you bind your application to the Xsuaa service instance. With these elements in place, you can leverage the token flows in your Java application.

## Requirements
- [Apache HttpClient 4.5](https://hc.apache.org/httpcomponents-client-4.5.x/index.html)

## Table of Contents
1. [Setup](#setup)
   - [1.1 Spring applications](#11-configuration-for-spring-applications)
   - [1.2 Java EE web applications](#12-configuration-for-java-ee-applications)
   - [Identity service configuration setup](#oauth2serviceconfiguration)
   - [HTTP Client setup](#httpclientfactory)
   - [Cache configuration](#cache-configuration)
2. [API Usage](#token-flows-api-usage)
   - [2.1. Jwt Bearer Token Flow](#jwt-bearer-token-flow)
   - [2.2. Client Credentials Token Flow](#client-credentials-token-flow)
   - [2.3. Refresh Token Flow](#refresh-token-flow)
   - [2.4. Password Token Flow](#password-token-flow)
3. [Troubleshooting](#troubleshooting)
4. [Samples](#samples)

## Setup 
For Spring Boot applications `TokenFlows` come autoconfigured with our `spring-security` or `spring-xsuaa` libraries and can be easily consumed by autowiring the `XsuaaTokenFlows` Bean. For more details see [1.1. Configuration for Spring Applications](#11-configuration-for-spring-applications) section.

For a **Java EE application** you will need to provide
[OAuth2ServiceConfiguration](#oauth2serviceconfiguration) and [HttpClientFactory](#httpclientfactory) to set up `XsuaaTokenFlows`. See [1.2. Configuration for Java EE Applications](#12-configuration-for-java-ee-applications) section for more details.

There is also a Cache provided that caches up to 1000 tokens for 10 minutes. For Spring Boot autoconfigured `XsuaaTokenFlows` it is only possible to [disable cache per each request](#disable-cache-for-a-single-request--runtime-). 
If you want to change cache settings you have to [overwrite the autoconfigured](#custom-xsuaatokenflows-bean) `XsuaaTokenFlows` Bean.
See more details in [Cache](#cache-configuration) section.

### 1.1. Configuration for Spring Applications
#### Maven Dependencies
In context of a Spring Boot application you can leverage autoconfiguration provided by the following library:
```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>resourceserver-security-spring-boot-starter</artifactId>
    <version>3.3.1</version>
</dependency>
```
In context of Spring Applications you will need the following dependencies:
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client</artifactId>
    <version>3.3.1</version>
</dependency>
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
</dependency>
```

#### XsuaaTokenFlows Initialization
As autoconfiguration requires Spring Boot specific dependencies, it is enabled when using `resourceserver-security-spring-boot-starter` Spring Boot Starter.
Then `spring-security` library autoconfigures beans, that are required to initialize the Token Flows API.

| Auto-configuration class                                                                                                                          | Description                                                                                                                                                                                         |
|---------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [XsuaaTokenFlowAutoConfiguration](../spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/XsuaaTokenFlowAutoConfiguration.java) | Configures a `XsuaaTokenFlows` bean with the [xsuaaServiceConfiguration](#autoconfigured-OAuth2ServiceConfiguration-Bean) Bean  and [tokenFlowHttpClient](#autoconfigured-tokenFlowHttpClient) Bean |

To consume the `XsuaaTokenFlows` class, you simply need to `@Autowire` it like this:
```java
@Autowired
private XsuaaTokenFlows xsuaaTokenFlows;
```

#### Custom XsuaaTokenFlows Bean
For non Spring Boot Applications or if the `XsuaaTokenFlowAutoConfiguration` doesn't fit to your use case you can provide your own `XsuaaTokenFlows` Bean.

```java
import com.sap.cloud.security.annotation.Beta;
import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;

@Configuration
public class CustomConfiguration {

	@Bean
	public OAuth2ServiceConfiguration customServiceConfiguration() {
		return OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
                .withClientId(...)
                .withCertificate(...)
                .withPrivateKey(...)
                .withUrl(...)
                .withCertUrl(...).build();
	}

	@Bean
	public CloseableHttpClient customHttpClient(OAuth2ServiceConfiguration customServiceConfiguration) {
		return HttpClientFactory.create(customServiceConfiguration.getClientIdentity());
	}

	@Bean
	public XsuaaTokenFlows customTokenFlows(CloseableHttpClient customHttpClient, OAuth2ServiceConfiguration customServiceConfiguration) {
		return new XsuaaTokenFlows(
						new DefaultOAuth2TokenService(customHttpClient),
						new XsuaaDefaultEndpoints(customServiceConfiguration),
				        customServiceConfiguration.getClientIdentity()
        );
	}
}
```
See the [OAuth2ServiceConfiguration](#oauth2serviceconfiguration) section and [HttpClientFactory](#httpclientfactory) for more detailed information about the involved classes.

### 1.2. Configuration for Java EE Applications
#### Maven Dependencies
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client</artifactId>
    <version>3.3.1</version>
</dependency>
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
</dependency>
```

#### XsuaaTokenFlows Initialization
```java
XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
                                    new DefaultOAuth2TokenService(CloseableHttpClient), 
                                    new XsuaaDefaultEndpoints(OAuth2ServiceConfiguration),
                                    OAuth2ServiceConfiguration.getClientIdentity()));
```
The `XsuaaTokenFlows` needs to be instantiated with a `DefaultOAuth2TokenService`, `XsuaaDefaultEndpoints` and `ClientIdentity`.

- `OAuth2ServiceConfiguration` is placeholder for the Identity service configuration, see [here](#oauth2serviceconfiguration) how to initialize it

- `CloseableHttpClient` is a placeholder for the Apache HTTP client, see [here](#httpclientfactory) how to initialize it

### OAuth2ServiceConfiguration
`OAuth2ServiceConfiguration` holds the information from the respective Identity service binding and is used in `XsuaaTokenFlows` initialization.

#### Autoconfigured OAuth2ServiceConfiguration Bean
When using `spring-xsuaa` or `spring-security` client libraries, a readily configured OAuth2ServiceConfiguration is accessible via `XsuaaServiceConfiguration` Bean.

#### Default OAuth2ServiceConfiguration
Alternatively, the `env` library provides a convenient way to obtain bound Identity service configurations by reading information from the `VCAP_SERVICES` environment variable or K8s secrets and mapping it to an instance of the `OAuth2ServiceConfiguration` class. You can use it as follows:
```java
OAuth2ServiceConfiguration config = Environments.getCurrent().getXsuaaConfiguration();
```

#### Custom OAuth2ServiceConfiguration
If you need to fetch a token from a specific Identity service instance that is not bound to your application, e.g. the uaa service configuration of your job scheduler, you need to initialize an `OAuth2ServiceConfiguration` manually. You can use the `OAuth2ServiceConfigurationBuilder` provided by the `env` library for this purpose.

```java
OAuth2ServiceConfigurationBuilder builder = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA);
OAuth2ServiceConfiguration config = builder.withClientId(...)
                                           .withClientSecret(...)
                                           .withCertificate(...)
                                           .withPrivateKey(...)
                                           .withUrl(...)
                                           .withCertUrl(...).build();
```

#### Externally managed certificate
To utilize an **externally managed certificate** in 
- Java EE application: you need to modify the `OAuth2ServiceConfiguration` instance with the external key:
    ```java
   OAuth2ServiceConfigurationBuilder builder = OAuth2ServiceConfigurationBuilder.fromConfiguration(Environments.getCurrent().getXsuaaConfiguration());
   OAuth2ServiceConfiguration config = builder.withPrivateKey("-----BEGIN RSA PRIVATE KEY ... END RSA PRIVATE KEY-----").build();
    ```
- Spring Boot applications:
  A `ClientCertificate` needs to be instantiated with the external key and the `XsuaaTokenFlows` bean needs to be overwritten using this `ClientCertificate` instance. <br>Alternatively you can provide the certificate key property programmatically by defining default property.
   ```java
    @SpringBootApplication
    public class Application {
        public static void main(String[] args) {
          
            SpringApplication application = new SpringApplication(Application.class);
            Properties properties = new Properties();
          
            properties.put("xsuaa.key", "-----BEGIN RSA PRIVATE KEY ... END RSA PRIVATE KEY-----"); // when using spring-xsuaa
            properties.put("sap.security.services.xsuaa.key", "-----BEGIN RSA PRIVATE KEY ... END RSA PRIVATE KEY-----"); // when using spring-security
          
            application.setDefaultProperties(properties);
            application.run(args);
          
        }
    }
   ```

  :information_source: For **testing purposes only** `key` can be overwritten in `application.yml` properties file.
   ```yaml
      # spring-xsuaa
      xsuaa:
        key: -----BEGIN RSA PRIVATE KEY ... END RSA PRIVATE KEY-----
      # spring-security
      sap.security.services.xsuaa:
        key: -----BEGIN RSA PRIVATE KEY ... END RSA PRIVATE KEY-----
    ```
    :exclamation: **DO NOT** disclose your key or secret in publicly available places e.g. repository in GitHub.com

:bulb: Note that if you are only using the `token-client` library without the [java-security](../java-security/README.md) or [spring-security](../spring-security/README.md), you will need to define the `env` dependency in your pom.xml:
```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>env</artifactId>
</dependency>
```

### HttpClientFactory
`HttpClientFactory` creates an HTTP client that will make the requests to the corresponding Identity service.

#### Autoconfigured tokenFlowHttpClient
When using `resourceserver-security-spring-boot-starter` Spring Boot Starter client library, a readily configured `CloseableHttpClient` is accessible via `tokenFlowHttpClient` Bean that uses the `HttpClientFactory` internally to set up the HTTP Client for token flows.

#### Default HttpClientFactory
The Token Client library includes a default implementation [DefaultHttpClientFactory](./src/main/java/com/sap/cloud/security/client/DefaultHttpClientFactory.java), of the [HttpClientFactory](./src/main/java/com/sap/cloud/security/client/HttpClientFactory.java) interface. 
It creates a preconfigured [Apache HttpClient 4](https://hc.apache.org/httpcomponents-client-4.5.x/index.html) with the given [ClientIdentity](../java-api/src/main/java/com/sap/cloud/security/config/ClientIdentity.java) for the Identity service instance.

To acquire the HTTP client, use the following code:
```java
CloseableHttpClient client = HttpClientFactory.createClient(ClientIdentity clientIdentity); // you can obtain ClientIdentity by invoking the OAuthServiceConfiguration.getClientIdentity() method
```

`DefaultHttpClientFactory` HTTP Clients are configured in the following way:
- connection pool
    - maximum of 200 total connections
    - 50 connections per route.
- connection and connection request timeouts -  5 seconds
- socket timeout 30 seconds

:information_source: These values are intended as an initial configuration, and you should monitor your application's performance and provide your own `HttpClientFactory` implementation, if you observe performance degradation.
For more information, refer to the [Troubleshooting](#insufficient-performance-for-token-validations-or-token-flows) section.

### Cache Configuration

By default, the `OAuth2TokenService` implementations (`DefaultOAuth2TokenService` and `XsuaaOAuth2TokenService`) are caching tokens internally.
By default up to 1000 tokens are cached for 10 minutes and the statistics are disabled.
The Cache can be individually configured by configuring `TokenCacheConfiguration` class. `XsuaaTokenFlows` need to be then initialized with the `DefaultOAuth2TokenService` or `XsuaaOAuth2TokenService` that takes `TokenCacheConfiguration` as a constructor parameter.

#### Cache configuration options:
```java
TokenCacheConfiguration tokenCache = TokenCacheConfiguration.getInstance(
		Duration cacheDuration,
                int cacheSize, 
                Duration tokenExpirationDelta,
		boolean cacheStatisticsEnabled);
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(CloseableHttpClient, tokenCache);
XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService, ..., ...);
```
#### Disable Cache
The cache can be disabled by using the `TokenCacheConfiguration.cacheDisabled()` configuration as follows:
```java
OAuth2TokenService tokenService = new DefaultOAuth2TokenService(CloseableHttpClient, TokenCacheConfiguration.cacheDisabled());
XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService, ..., ...);
```
:exclamation: In order to leverage the cache it makes sense to have only one reference to the `OAuth2TokenService` implementation or to the `XsuaaTokenFlows`.

#### Disable Cache for a single request (runtime)
```java
tokenFlows.clientCredentialsTokenFlow().disableCache(true).execute();
```

#### Clear cache (runtime)
```java
AbstractOAuth2TokenService tokenService = new DefaultOAuth2TokenService(CloseableHttpClient);
XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService, ..., ...);
// runtime in case of reoccurring issues
tokenService.clearCache();
```

## Token Flows API usage
The `XsuaaTokenFlows` provides a builder-pattern API that allows applications to easily create and execute each flow, guiding developers to only set properties that are relevant for the respective token flow.

### Jwt Bearer Token Flow
In order to exchange an access token for a different service:

```java
OAuth2TokenResponse tokenResponse = tokenFlows.jwtBearerTokenFlow()
                                    .bearerToken(bearerToken)
                                    .zoneId("MY_ZONE_ID")           // optional
                                    .scopes("READ")                 // optional restriction of granted scopes
                                    .disableCache(true)             // optionally disables token cache for the request
                                    .execute();
```

### Client Credentials Token Flow
Obtain a client credentials token:

```java
OAuth2TokenResponse clientCredentialsToken = tokenFlows.clientCredentialsTokenFlow()
                                                    .zoneId("MY_ZONE_ID")               // optional
                                                    .disableCache(true)                 // optionally disables token cache for the request
                                                    .execute();
```

### Refresh Token Flow
In case you have a refresh token and want to obtain an access token:

```java
OAuth2TokenResponse refreshToken = tokenFlows.refreshTokenFlow()
                              .refreshToken(<refresh_token>)
                              .subdomain(jwtToken.getSubdomain()) // this is optional
                              .disableCache(true)                 // optionally disables token cache for request
                              .execute();
```

### Password Token Flow
In order to obtain an access token for a user:
```java
OAuth2TokenResponse tokenResponse = tokenFlows.passwordTokenFlow()
                                    .subdomain(jwtToken.getSubdomain()) 
                                    .username(<username>)
                                    .password(<user password>)
                                    .disableCache(true)  // optionally disables token cache for request
                                    .execute();
```


## Troubleshooting

To troubleshoot problems with the token client, you can set the logging level for the 
`com.sap.cloud.security` package to `DEBUG`. 
Have a look at the [Logging](/java-security/README.md#logging) section for more information on logging for Java EE applications.

If you need more detailed network data in your logs, you can also enable debugging for your HTTP client. For more information see
[Apache HTTP Client logging documentation](https://hc.apache.org/httpcomponents-client-4.5.x/logging.html).

:exclamation:Note that this might leak encoded tokens into your logs. Use with caution!

### Insufficient performance for token validations or token flows

If you observe performance degradation for token validation or token flows, `HttpClient` configuration should be adjusted according to your platform's requirements, infrastructure, and anticipated load. You should monitor the performance of your `HttpClient` under various loads and adjust these parameters accordingly to achieve optimal performance.

> You may need to configure the timeouts to specify how long to wait until a connection is established and how long a socket should be kept open (i.e. how long to wait for the (next) data package). As the SSL handshake is time-consuming, it might be recommended to configure an HTTP connection pool to reuse connections by keeping the sockets open. See also [Baeldung: HttpClient Connection Management](https://www.baeldung.com/httpclient-connection-management).<br>

To adjust the `HttpClient` parameters you will need to provide your own implementation of `HttpClientFactory` interface.

- Create an SPI configuration file with name `com.sap.cloud.security.client.HttpClientFactory` in ``src/main/resources/META-INF/services`` directory
- Enter the fully qualified name of your `HttpClientFactory` implementation class, e.g. `com.mypackage.CustomHttpClientFactory`
- The implementation could look like:
````java
public class CustomHttpClientFactory implements HttpClientFactory {

    public CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
        // here comes your implementation
    }
}
````
:bangbang: For your custom `CloseableHttpClient` implementation always disable redirects :bangbang:


### Common Pitfalls
#### This module requires the [JSON-Java](https://github.com/stleary/JSON-java) library
If you have classpath related  issues involving JSON you should take a look at the
[Troubleshooting JSON class path issues](../docs/Troubleshooting_JsonClasspathIssues.md) document.

#### Token exchange `Unable to map issuer`
```bash
{\"error\":\"unauthorized\",\"error_description\":\"Unable to map issuer, [http://subdomain.localhost:8080/uaa/oauth/token] , to a single registered provider\"}
```  
Token exchange is only supported within the same Identity zone/tenant. That means, that you have to call the `/oauth/token` endpoint of the same subdomain, that was used for the original token. This can be achieved by configuring the JWT Bearer Token Flow the following way:
````
tokenFlows.jwtBearerTokenFlow().token(jwtToken).subdomain(jwtToken.getSubdomain());
````

#### In Spring: `UnsatisfiedDependencyException`
For Spring applications error like
```bash
java.lang.IllegalStateException: Failed to load ApplicationContext 
Caused by: org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name 'securityConfiguration': Unsatisfied dependency expressed through field 'xsuaaTokenFlows'
nested exception is java.lang.NoClassDefFoundError: org/apache/http/client/HttpClient
``` 
indicates that mandatory `org.apache.httpcomponents:httpclient` dependency is missing in your POM.

## Samples
- [Java sample](/samples/java-tokenclient-usage)
- [Spring Boot sample](/samples/spring-security-xsuaa-usage)
