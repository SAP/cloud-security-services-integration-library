# XSUAA Token Client and Token Flow API

## Motivation

This library serves as slim client for some XSUAA `/oauth/token` token endpoints as specified [here](https://docs.cloudfoundry.org/api/uaa/version/4.30.0/index.html#token). 
Furthermore it introduces a new API to support the following token flows:

* User Token Flow
* Client Credentials Flow
* Refresh Token Flow

The Authorization Code Grant Flow involves the browser and is therefore triggered by an API gateway (e.g. Application Router). The other flows, however, may need to be triggered programmatically, e.g. to exchange one token for another or refresh a token, if it is about to expire. When you create a XSUAA service instance a OAuth client gets created and you receive the client credentials (client id and secret) when you bind your application with the XSUAA service instance. Having that in place you are ready to use the token flows in your Java application.

## Configuration for Java Applications

### Maven Dependencies
```xml
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-web</artifactId>
</dependency>
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>token-client</artifactId>
    <version>1.7.0</version>
</dependency>
```
## Configuration for Spring Boot Applications

### Maven Dependencies
In context of a Spring Boot application you may like to leverage auto-configuration:
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>xsuaa-spring-boot-starter</artifactId>
    <version>1.7.0</version>
</dependency>
```

### Auto-configuration
As auto-configuration requires Spring Boot specific dependencies, it is enabled when using `xsuaa-spring-boot-starter` Spring Boot Starter. 
Then, xsuaa integration libraries auto-configures beans, that are required to initialize the Token Flows API.

Auto-configuration class | Description
---- | --------
[XsuaaAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaAutoConfiguration.java) | Adds `xsuaa.*` properties to Spring's Environment. The properties are by default parsed from `VCAP_SERVICES` system environment variables and can be overwritten by properties such as `xsuaa.url` e.g. for testing purposes. Furthermore it exposes a `XsuaaServiceConfiguration` bean that can be used to access xsuaa service information.  Alternatively you can access them with `@Value` annotation e.g. `@Value("${xsuaa.url:}") String xsuaaBaseUrl`. As of version `1.7.0` it creates a default [`RestTemplate`](https://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/client/RestOperations.html) bean that serves as Rest client that is used inside a default `OAuth2TokenService` to perform HTTP requests to the XSUAA server. **It is recommended to overwrite this default and configuring it with the HTTP client of your choice.**
[XsuaaTokenFlowAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaTokenFlowAutoConfiguration.java) | Configures a `XsuaaTokenFlows` bean with a `RestOperations` and `XsuaaServiceConfiguration` bean to fetch the XSUAA service binding information.

You can gradually replace auto-configurations as explained [here](https://docs.spring.io/spring-boot/docs/current/reference/html/using-boot-auto-configuration.html).

## Usage
The flows themselves provide a builder-pattern API that allows applications to easily create and execute each flow, guiding developers to only set properties that are relevant for the respective token flow.

To consume the `XsuaaTokenFlows` class, you simply need to `@Autowire` it like this:
```java
@Autowired
private XsuaaTokenFlows xsuaaTokenFlows;
```

Or, alternatively you can instantiate it like that
```java
String clientId     = "<<client id from XSUAA service binding>>";
String clientSecret = "<<client secret from XSUAA service binding>>";
String xsuaaBaseUrl = "<<xsuaa base url from XSUAA service binding>>";

OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(xsuaaBaseUrl);
ClientCredentials clientCredentials = new ClientCredentials(clientId, clientSecret);
RestOperations restOperations = new RestTemplate();

XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(restOperations, endpointsProvider, clientCredentials);
```

Then, to create a **client credentials token flow** very easily by the following code:

```java
OAuth2TokenResponse clientCredentialsToken = tokenFlows.clientCredentialsTokenFlow()
                                                    .execute();
```

In case you have a refresh_token value and want to refresh an existing token with it, you can do the following:

```java
OAuth2TokenResponse refreshToken = tokenFlows.refreshTokenFlow()
                                        .refreshToken("<<Your refresh token goes here. You get this from the OAuth server.>>")
                                        .execute();
```

Finally, to create a **user token flow** (to exchange one Jwt token for another), you can do the following:

```java
XsuaaToken jwtToken = SpringSecurityContext.getToken();

OAuth2TokenResponse userToken = tokenFlows.userTokenFlow()
                .token("<<Your current User access token goes here.>>")
                .clientId("other's client id") // this is optional!
                .subdomain(jwtToken.getSubdomain()) // this is optional      
                .attributes(additionalAttributes) // this is optional!
                .execute();
```

Make sure to read the API documentation of the `XsuaaTokenFlows` API, to understand what the individual token flows' parameters are for.
Also note, that the **user token flow** requires an input token that has the scope `uaa.user` to succeed. 

Have a look at [`TestController.java`](/samples/spring-security-xsuaa-usage/src/main/java/sample/spring/xsuaa/TestController.java) for sample code.
