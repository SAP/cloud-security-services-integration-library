# Change Log 

All notable changes to this project will be documented in this file.

## 2.6.2
- [java-security] `XSUserInfoAdapter` provides full compatible implementation of `com.sap.xsa.security.container.XSUserInfo.java` interface.

## 2.6.1
- [spring-xsuaa] SpringSecurityContext throws `AccessDeniedException` instead of `IllegalStateException` when authentication does not contain principal of type Token.
- [java-security] `JwtAudienceValidator` Support Audience Validation of Xsuaa Broker clones (multiple xsuaa bindings): NGPBUG-111540.
- [java-security-test] Basic support fo JUnit 5 (Jupiter).
- [java-security-test] Deprecation: `SecurityTestRule#getWireMockRule()` needs to be replaced by `getWireMockServer()`.
- [java-security-test] One instance of `SecurityTestRule` should run only one WireMock server. With that `@ClassRule SecurityTestRule` can be declared in a base class.

## 2.5.3
- [spring-xsuaa] `XsuaaJwtDecoder` supports verificationkey from `VCAP_SERVICES` as fallback public key.
- [spring-xsuaa] when using `auto-configuration` and expose your own `RestTemplate` `RestOperations` bean, have a look at this [documentation](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/spring-xsuaa#resttemplate--restoperations).
- [java-security-test] `JwtGenerator` supports `withLocalScopes()`.
- [java-security] `SapIdToken` should return value of claim "sap_uid" (SAPGlobalUserID) as Principal name.
- [java-security] `JwtAudienceValidator` Support Audience Validation of Xsuaa Broker clones: NGPBUG-111540.
- [java-api] enhanced with config interfaces, which are relevant for SAP Java Buildpack.
- [api] changes `XSUserInfoException` from `Exception` to `RuntimeException`. This reflects the json-lib change in `java-container-security` (version `3.12.0`).

## 2.5.2
- [java-api], [java-security], [token-client] works with logger api `slf4j-api` and does no longer provide the slf4j-implementation. Please have a look at the [java-security/README.md#logging](https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/java-security/README.md#logging) documentation.
- [xsuaa-spring-boot-starter] update spring-boot (security) dependency versions [#239](https://github.com/SAP/cloud-security-xsuaa-integration/issues/239).
- [java-security-test] `SecurityTestRule.setKeys` allows to customize private/public keys that are located in the resource path, e.g. `src/main/resources` or `src/test/resources`.
- [java-security-test] configures the modulus of the public key provided by `WireMock`. With that the public key can be consumed by the Nimbus Jwt decoder.
- [samples/spring-security-xsuaa-usage] demonstrates how to setup JUnit tests using `java-security-test` library.

## 2.5.1
- [java-api] As preparation for the SAP Java Buildpack the interfaces, as well as the `SecurityContext` is extracted to [java-api](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/java-api).
- [java-security] `AccessToken`s provided via the `SpringSecurityContext` should also support the `hasLocalScope` method.

## 2.5.0
- [java-security-test] `JwtGenerator.withClaimsFromFile` accepts claims from a file.
- [java-security] Provides with `SpringSecurityContext` an alternative way of accessing jwt tokens for Spring applications in asynchronous threads.
- [token-client] The `UserTokenFlow` has used the "user_token" grant type together with the "refresh_token" grant type in order to do the token exchange.
After the consumption of UAA 4.27 we can adapt the grant type "urn:ietf:params:oauth:grant-type:jwt-bearer". 
This reduces the round trips to the XSUAA from 2 to 1. Further, it eliminates the need for the user to have scope "uaa.user". The feature flag `xsuaa.userTokenFlow.useJwtBearer` has become obsolete. 

## 2.4.5
- [java-security] Initial / released version of the new plain Java security libraries as documented [here](/README.md#token-validation-for-java-applications).

## 2.3.2
- [spring-xsuaa] Fix vulnerability issues and increased Spring versions.
- [spring-xsuaa] **Bug fix** in TokenBrokerResolver: Second configured authentication method was ignored.

## 2.3.0
- Issue: Spring tests fail with version `2.2.0`, when auto-configuration is disabled and no `RestOperations` bean is specified.
- [token-client] Supports basically JWT Bearer Token Grant as documented [here](https://docs.cloudfoundry.org/api/uaa/version/74.4.0/index.html#jwt-bearer-token-grant).
- [token-client] **Bug fix** for state issue in HttpHeaderFactor ([#200](/issues/200)) that causes interference between different types of token flows.
- [spring-xsuaa] Supports (ignores) xsuaa bindings of plan "apiaccess".

## 2.2.0
- [spring-xsuaa] `PropertySourceFactory` supports custom property sources and default can optionally be disabled with  `spring.xsuaa.disable-default-property-source=true`
- [spring-xsuaa] Supports Spring Core `5.2.0.RELEASE`and Spring Boot `2.2.0.RELEASE`
- [spring-xsuaa] Deprecates `TokenUrlUtils` in favor of `OAuth2ServiceEndpointsProvider`
- Internally, we've cleaned up maven dependencies (converged versions) and 
  - removed transient dependency of `spring-security-oauth2` to `jackson`.
  - introduced `org.owasp.dependency-check-maven` which performs CVSS checks.
- [token-client] Supports password token flows as documented [here](/token-client).

## 2.1.0
* `token-client` library supports [Apache Http Client](https://hc.apache.org/) (without any Spring dependencies). Have also a look at the [java-tokenclient-usage](/samples/java-tokenclient-usage) sample application.
* Fix CVE-2018-1000613 by removing unnecessary dependencies ([issue 144](https://github.com/SAP/cloud-security-xsuaa-integration/issues/144)).
* Makes `XsuaaMockWebServer` more robust.

## 2.0.0
* Deleted package `com.sap.xs2.security.container` in order to avoid Class Loader issues, when an application makes use of SAP-libraries using the SAP-internal container lib like CAP. 
  - As already mentioned use `SpringSecurityContext` class instead of `SecurityContext` class.
* Removed deprecated methods:
  - `XsuaaServiceConfiguration.getTokenUrl()`
  - `XsuaaToken.getClaimAccessor()` is not required anymore as `Xsuaa` itself implements `JwtClaimAccessor `.
* Deprecated `TokenBroker` interface and its implementation `UaaTokenBroker`, as this is going to be replaced with the `OAuth2TokenService` interface which is provided by the new `token-client` library. If you wish to configure / pass your `RestTemplate` you can pass an instance of `OAuth2TokenService`:  

```java
new TokenBrokerResolver( 
  <<your configuration>>, 
  <<your cache>>, 
  new XsuaaOAuth2TokenService(<<your restTemplate>>), 
  <<your authenticationInformationExtractor>>);
```
* `TokenUlrUtils` class is now package protected and will be deleted with version.
* `token-client` library supports basically Password-Grant Access Tokens.


## 1.7.0
* We now provide a new slim [`token-client`](/token-client/README.md) library with a `XsuaaTokenFlows` class, which serves as a factory for the different flows (user, refresh and client-credentials). This deprecates the existing `Token.requestToken(XSTokenRequest)` API. 
  * The `token-client` library can be used by plain Java applications. 
  * Auto-configuration is provided for Spring Boot applications only, when using XSUAA Spring Boot Starter. 

* **ANNOUNCEMENT: Please be aware that with version `2.0.0` we want to get rid of package `com.sap.xs2.security.container` in order to avoid Class Loader issues, when an application makes use of SAP-libraries using the SAP-internal container lib.**


## 1.6.0
* Provides spring starter for spring-xsuaa, which enables auto-configuration
* Supports reactive ServerHttpSecurity (Spring webflux). Have a look at the (webflux sample application)[samples/spring-webflux-security-xsuaa-usage/README.md]
* Some enhancements for XSUAA integration
* To make sure that the Spring SecurityContext is always initialized with a validated token use `SpringSecurityContext.init()` method as documented [here](spring-xsuaa/README.md)
* Use `SpringSecurityContext` instead of `SecurityContext`, which gets deprecated in this version. 

### Incompatible changes
* As of version `1.6.0` you need to make use of XSUAA Spring Boot Starter in order to leverage auto-configuration (see "Troubleshoot" section [here](spring-xsuaa/README.md#troubleshoot))


## 1.5.0
* Supports `jku` URI which is provided as part of the JSON Web Signature (JWS). The `jku` of the Jwt token header references the public key URI of the Xsuaa OAuth Authorization Server, and needs to match to the `xsuaa.uaadomain`.
* Completely customizable auto-configurations so that apps can override the spring-xsuaa defaults:
  * auto-configuration for Xsuaa OAuth Authorization Server is documented [here](spring-xsuaa#auto-configuration).
  * auto-configuration for Xsuaa Mock Server configuration can be found [here](spring-xsuaa-mock/src/main/java/com/sap/cloud/security/xsuaa/mock/autoconfiguration/XsuaaMockAutoConfiguration.java).
* Uses apache slf4j Logger for better log analysis on Cloud Foundry. This is provided with org.springframework.boot:spring-boot-starter-logging.
* Improves and enhances [sample application](samples/spring-security-xsuaa-usage).
* Renames class `TokenImpl` to `XsuaaToken`. Furthermore for convenience `XsuaaToken` subclasses `org.springframework.security.oauth2.jwt.Jwt`.
* Subclassing of `TokenAuthenticationConverter` is no longer allowed, instead `TokenAuthenticationConverter` can be configured with your own `AuthoritiesExtractor` implementation (an example can be found [here](spring-xsuaa/src/test/java/com/sap/cloud/security/xsuaa/token/TokenAuthenticationConverterTest.java#L103)).
* Please note that the port of the mock web server that is provided with the [xsuaa mock library](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/spring-xsuaa-mock) had to be defined statically. It runs now always on port 33195.
* Find more complex examples here: https://github.com/SAP/cloud-application-security-sample

## 1.4.0
* API method to query [token validity](spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/token/Token.java#L167)
* Bugfix in basic authentication support: allow  usage of JWT token or basic authentication with one configuration
* Allows overwrite / enhancement of XSUAA jwt token validators
* Allow applications to initialize of Spring SecurityContext for non HTTP requests. As documented [here](spring-xsuaa/README.md)

## 1.3.1
* Broker plan validation failed due to incorrect audience validation
## 1.3.0
* JwtGenerator offers enhancement options: custom claims and audience
* Test framework support for multi tenancy

## 1.2.0
* Eases enhancement of TokenAuthenticationConverter ([issue 23](https://github.com/SAP/cloud-security-xsuaa-integration/issues/23))
* Makes XsuaaAudienceValidator more robust ([issue 21](https://github.com/SAP/cloud-security-xsuaa-integration/issues/21))
* XSTokenRequest accepts custom RestTemplate ([issue 25](https://github.com/SAP/cloud-security-xsuaa-integration/issues/25))
* Provides spring-xsuaa-test library with JWTGenerator ([issue 29](https://github.com/SAP/cloud-security-xsuaa-integration/issues/29))
* Provides spring-xsuaa-mock library with XSUAA authentication mock web server for offline token key validation ([issue 30](https://github.com/SAP/cloud-security-xsuaa-integration/issues/30))


## 1.1.0

* Spring-Security 5 integration libraries. Added AudienceValidator
* Spring-Security 5 Support for basic authentication

## 1.1.0.RC1

* Initial version including spring-security 5 integration libraries


## 1.0.0

* Initial version of the api for SAP Java Buildpack

