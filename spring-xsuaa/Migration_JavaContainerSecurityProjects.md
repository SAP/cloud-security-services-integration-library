# Migration Guide for Applications that use Spring Security and java-container-security

This migration guide is a step-by-step guide explaining how to replace the following SAP-internal Java Container Security Client libraries
- com.sap.xs2.security:java-container-security
- com.sap.cloud.security.xsuaa:java-container-security

with this open-source version.

**Please note, that this Migration Guide is NOT intended for applications that leverage token validation and authorization checks using SAP Java Buildpack.** This [documentation](https://github.com/SAP/cloud-security-xsuaa-integration#token-validation-for-java-web-applications-using-sap-java-buildpack) describes the setup when using SAP Java Buildpack.

## Overview

The following list serves as an overview of this guide and points out sections that describe required code changes for migrating applications.

- Spring 5 is required! See section [Prerequisite](#prerequisite-migrate-to-spring-5).
- Maven dependencies need to be changed. See section [Maven Dependencies](#maven-dependencies).
- The Spring Security configuration needs changes described in section [Configuration changes](#configuration-changes).
- `Token` instead of `XSUserInfo`. See section [Fetch data from token](#fetch-data-from-token).
- If your application has multiple XSUAA bindings, see section [Multiple bindings](#multiple-xsuaa-bindings).

## Prerequisite: Migrate to Spring 5

If your application does not already use Spring 5 you need to upgrade to Spring
5 first to use [spring-xsuaa](/spring-xsuaa).
Likewise if you use Spring Boot make sure that you use Spring Boot 2.

Your application is probably using Spring Security OAuth 2.x which is being deprecated with
Spring 5. The successor is Spring Security 5.2.x but it is not 100% compatible with Spring
Security OAuth 2.x. See the
[official migration guide](https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide)
for more information.

We already migrated the [cloud-bulletinboard-ads](https://github.com/SAP-samples/cloud-bulletinboard-ads/)
application. You take look at 
[this commit](https://github.com/SAP-samples/cloud-bulletinboard-ads/commit/cffe04c95ae06e5b9c56fa827585bd127b57a765)
which shows what had to be changed to migrate an application from Spring 4 to Spring 5.

## Maven Dependencies
To use the new [spring-xsuaa](/spring-xsuaa) client library the dependencies declared in maven `pom.xml` need to be changed.
See the [docs](/spring-xsuaa#configuration) on what to add to your `pom.xml`.
After you have added to new dependencies you are ready to **remove** the **`java-container-security`** client library by
deleting the following lines from the pom.xml:
```xml
<dependency>
  <groupId>com.sap.xs2.security</groupId>
  <artifactId>java-container-security</artifactId>
</dependency>
<dependency>
  <groupId>com.sap.xs2.security</groupId>
  <artifactId>java-container-security-api</artifactId>
</dependency>
```
Or
```xml
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>java-container-security</artifactId>
</dependency>
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>api</artifactId>
</dependency>
```

Make sure that you do not refer to any other sap security library with group-id `com.sap.security` or `com.sap.security.nw.sso.*`. 

## Configuration changes
After the dependencies have been changed, the spring security configuration needs some adjustments as well.

One difference between `java-container-security` and [spring-xsuaa](/spring-xsuaa) is that spring-xsuaa
does not provide the `SAPOfflineTokenServicesCloud` class. This is because `SAPOfflineTokenServicesCloud` requires 
Spring Security Oauth 2.x which is being deprecated in Spring 5.
This is documented in the official [migration guide](https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide).

This means that you have to remove the  `SAPOfflineTokenServicesCloud` bean from your security configuration
and adapt the `HttpSecurity` configuration. This involves the following steps:

- The `@EnableResourceServer` annotation must be removed because the resource server is now configured using the Spring Security DSL syntax. See the [docs](/spring-xsuaa/#setup-security-context-for-http-requests) for an example configuration.
- The `antMatchers` must be configured to check against the authorities. For this the `TokenAuthenticationConverter`
  needs to be configured like described in the [docs](/spring-xsuaa/#setup-security-context-for-http-requests).

We already migrated the [cloud-bulletinboard-ads](https://github.com/SAP-samples/cloud-bulletinboard-ads) application from
Spring 4 to Spring 5 and
[this commit](https://github.com/SAP-samples/cloud-bulletinboard-ads/commit/f5f085d94f30fe670aafdabc811fe07bc6533f6b)
shows the changes to the security relevant parts.
Also take a look at the
[security config](https://github.com/SAP-samples/cloud-bulletinboard-ads/commit/f5f085d94f30fe670aafdabc811fe07bc6533f6b#diff-791eb47e5dbb9bcd7e54c7dd36c9f9dfL1)
which contains the most security relevant changes.

## Fetch data from token

You may have code parts that requests information from the access token, like the user's name, its tenant, and so on. So, look up your code to find its usage.

```java
import com.sap.xs2.security.container.SecurityContext;
import com.sap.xs2.security.container.UserInfo;
import com.sap.xs2.security.container.UserInfoException;

try {
	UserInfo userInfo = SecurityContext.getUserInfo();
	String logonName = userInfo.getLogonName();
} catch (UserInfoException e) {
	// handle exception
}
```

There is no `UserInfo` anymore. To obtain the token from the thread local storage, you
have to use Spring's `SecurityContext` managed by the `SecurityContextHolder`.
It will contain a `com.sap.cloud.security.xsuaa.token.Token`.
This is explained in the [usage section](/spring-xsuaa#usage) of the documentation.

> Note, that no `XSUserInfoException` is raised, in case the token does not contain the requested claim.

### Special `XSUserInfo` methods
The `XSUserInfo` provides some special methods that are not available in
the `com.sap.cloud.security.xsuaa.token.Token`.

See the following table for methods that are not available anymore and workarounds.

| XSUserInfo method       | Workaround                                                                                       |
|-------------------------|--------------------------------------------------------------------------------------------------|
| `checkLocalScope`       | Checks if a local scopes ist contained in `scope` claim. See section [XsuaaToken](#xsuaatoken). |
| `checkScope`            | Checks if a scope is contained in `scope` claim. See section [XsuaaToken](#xsuaatoken).         |
| `getAttribute`          | Use `getXSUserAttribute`.                                                                        |
| `getDBToken`            | Not implemented.                                                                                 |
| `getHdbToken`           | Not implemented.                                                                                 |
| `getIdentityZone`       | This reads claim `zid`. See section [XsuaaToken](#xsuaatoken).                                  |
| `getIdentityZone`       | This reads claim `zid`. See section [XsuaaToken](#xsuaatoken).                                  |
| `getJsonValue`          | Not implemented.                                                                                 |
| `getSystemAttribute`    | This extracts data from `xs.system.attributes` claim. See section [XsuaaToken](#xsuaatoken).    |
| `getToken`              | Not implemented.                                                                                 |
| `hasAttributes`         | Use `getXSUserAttribute` and check of the attribute is available.                                |
| `isInForeignMode`       | Not implemented.                                                                                 |
| `requestToken`          | Not implemented.                                                                                 |
| `requestTokenForClient` | Not implemented.                                                                                 |
|                         |                                                                                                  |

#### XsuaaToken
The runtime type of `Token` is `XsuaaToken`. `XsuaaToken` provides additional
methods that can be used to extract data from the token since it is a subclass of
`org.springframework.security.oauth2.jwt.Jwt`. So you can for example read
claims with `getClaim` or check for claims with `containsClaim`. See the
[spring documentation](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/jwt/Jwt.html)
for more details.

## Testing
In your unit test you might want to generate jwt tokens and have them validated. The new
[java-security-test](/java-security-test) library provides it's own `JwtGenerator`. This can be embedded using the
new `SecurityTestRule`. See the following snippet as example:

```java
@ClassRule
public static SecurityTestRule securityTestRule =
	SecurityTestRule.getInstance(Service.XSUAA)
		.setKeys("/publicKey.txt", "/privateKey.txt");
```

Using the `SecurityTestRule` you can use a pre configured `JwtGenerator` to create JWT tokens with custom scopes for your tests. It configures the JwtGenerator in such a way that **it uses the public key from the [`publicKey.txt`](/java-security-test/src/main/resources) file to sign the token.**

```java
String jwt = securityTestRule.getPreconfiguredJwtGenerator()
    .withAppId(SecurityTestRule.DEFAULT_APP_ID)
    .withLocalScopes("Display", "Update")
    .createToken()
    .getTokenValue();
```

See the [java-security-test docs](/java-security-test) for more details.

### Enable local testing
For local testing you might need to provide custom `VCAP_SERVICES` before you run the application. 
The new security library requires the following key value pairs in the `VCAP_SERVICES`
under `xsuaa/credentials` for jwt validation:
- `"uaadomain" : "localhost"`
- `"verificationkey" : "<public key your jwt token is signed with>"`

Before calling the service you need to provide a digitally signed JWT token to simulate that you are an authenticated user. 
- Therefore simply set a breakpoint in `JwtGenerator.createToken()` and run your `JUnit` tests to fetch the value of `jwt` from there. 

Now you can test the service manually in the browser using the `Postman` chrome plugin and check whether the secured functions can be accessed when providing a valid generated Jwt Token.

## Things to check after migration 
When your code compiles again you should first check that all your unit tests are running again. If you can test your
application locally make sure that it is still working and finally test the application in cloud foundry.

## Troubleshoot

### Multiple XSUAA Bindings

If your application is bound to two XSUAA service instances (application and broker), you could run into issues like the following:

```
Caused by: java.lang.RuntimeException: Found more than one xsuaa binding. There can only be one.
at com.sap.cloud.security.xsuaa.XsuaaServicesParser.getJSONObjectFromTag(XsuaaServicesParser.java:91)
at com.sap.cloud.security.xsuaa.XsuaaServicesParser.searchXSuaaBinding(XsuaaServicesParser.java:72)
at com.sap.cloud.security.xsuaa.XsuaaServicesParser.getAttribute(XsuaaServicesParser.java:59)
at com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory.getConfigurationProperties(XsuaaServicePropertySourceFactory.java:65)
at com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory.createPropertySource(XsuaaServicePropertySourceFactory.java:55)
at org.springframework.context.annotation.ConfigurationClassParser.processPropertySource(ConfigurationClassParser.java:452)
at org.springframework.context.annotation.ConfigurationClassParser.doProcessConfigurationClass(ConfigurationClassParser.java:271)
at org.springframework.context.annotation.ConfigurationClassParser.processConfigurationClass(ConfigurationClassParser.java:242)
at org.springframework.context.annotation.ConfigurationClassParser.parse(ConfigurationClassParser.java:199)
at org.springframework.context.annotation.ConfigurationClassParser.parse(ConfigurationClassParser.java:167)
```
There is no support in the library for having two XSUAA bindings (yet). It call however still be doen by following a few simple steps thare are described
[here](https://jtrack.wdf.sap.corp/browse/NGPBUG-96581?focusedCommentId=1387138&page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment-tabpanel).

## Issues
In case you face issues to apply the migration steps feel free to open a Issue here on [Github.com](https://github.com/SAP/cloud-security-xsuaa-integration/issues/new).

## Samples
- [cloud-bulletinboard-ads](https://github.com/SAP-samples/cloud-bulletinboard-ads/blob/Documentation/Security/Exercise_24_MakeYourApplicationSecure.md)
- [spring-security-xsuaa usage sample](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/samples/spring-security-xsuaa-usage)
