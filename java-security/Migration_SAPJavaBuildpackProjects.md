# Migration Guide for J2EE Web Applications that use SAP Java Buildpack for securing their applications


**This document is only applicable for J2EE web applications securing their application with SAP Java Buildpack.** The SAP Java Buildpack version `x.y.z` does not any longer use Spring and deprecated SAP-internal security libraries and the tomcat principal object has changed incompatible. 

This migration document is a step-by-step guide explaining how to migrate existing web applications to SAP Java Buildpack version `x.y.z` and get rid of the deprecated SAP-internal apis.

## Prerequisites

Please note, this Migration Guide is only intended for applications, using SAP Java Buildpack. You're using the SAP Java Buildpack, if you can find the `sap_java_buildpack` in the deployment descriptor of your application, e.g. in your `manifest.yml` file.

Furthermore the Migration Guide is only relevant if you make use of `XSUserInfo` interface provided by any of SAP security libraries.

## Overview of all breaking changes

The following list is an overview of the breaking changes that might require changes in existing
applications.

- New security related maven dependencies, see [Maven Dependencies](#maven).
- `AccessToken` instead of `XSUserInfo` in tomcat principal object. Use [XSUserInfoAdapter](#xs-user) to overcome the incompatible api change.

## Step 1: Adapt Maven dependencies <a name="maven"></a>

Your buildpack application has probably in the `pom.xml` a dependency to one of the deprecated sap-internal security api projects:

groupId (deprecated) | artifactId (deprecated) 
--- | --- 
com.sap.xs2.security | api 
com.sap.cloud.security.xssec | api 
com.sap.cloud.security.xsuaa | java-container-security-api 
com.sap.cloud.security.xsuaa | api

**If you do not have any of the api projects above as dependency you can skip this chapter!**

The above mentioned dependencies must be replaced with those, containing the compatibility layer:

```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-api</artifactId>
    <version>2.6.1</version>
    <scope>provided</scope> <!-- provided with buildpack -->
</dependency>
<!-- not provided anymore with buildpack -->
<!--dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>api</artifactId>
    <version>2.6.1</version>
</dependency-->
<!-- compatibility layer: XSUserInfoAdapter -->
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-security</artifactId>
    <version>2.6.1</version>
    <exclusions>
        <exclusion>
            <artifactId>slf4j-api</artifactId>
            <groupId>org.slf4j</groupId>
        </exclusion>
    </exclusions>
</dependency>
```
#### Explanation
- The dependency `com.sap.cloud.security:java-api` is the new api exposed by the SAP Java Buildpack as of version `x.y.z`.
- The dependency `com.sap.cloud.security.xsuaa:api` defines the `XSUserInfo` and is not anymore provided by the buildpack and must be added **without** `<scope>provided</scope>`. For now we comment it to detect all relevant places, we have to migrate.
- The dependency `com.sap.cloud.security:java-security` implements the `XSUserInfoAdapter` for compatibility reasons.
  - If you use `com.sap.cloud.security:java-security` in your application and deploy it via the SAP Java buildpack, you will need to exclude the `slf4j-api` dependency of `java-security` to avoid classpath issues. This is because the buildpack provides its own version of `slf4j-api`.

As you've commented the `com.sap.cloud.security.xsuaa:api` dependency, you will most likely have compile error at places where the api module was used. Those are the parts of the
application where information from the token (or user info) was read.  

See the next sections on how to migrate that.


## Step 2: Migrate XSUserInfo usages <a name="xs-user"></a>

In the former version of the buildpack the user principal could be obtained via:

```java
XSUserInfo userInfo = (XSUserInfo) request.getUserPrincipal();
```

This is not possible anymore because getUserPrincipal does not return an object of type `XSUserInfo`. Instead it returns an
`com.sap.cloud.security.token.AccessToken` object which can be wrapped by the adapter by `XSUserInfoAdapter` like so:

```java
XSUserInfo userInfo = new XSUserInfoAdapter(request.getUserPrincipal());
```

#### Explanation
The `XSUserInfoAdapter` class is a wrapper for `AccessToken` that implements the `XSUserInfo` interface and provides the functionality that was implemented in the java-container-security library.  The `XSUserInfoAdapter` class is part of the [`java-security`](#maven) module and needs to be added to your project as a dependency. You also need the legacy `api` project that contains the `XSUserInfo` interface.


## Step 3: Things to check after migration
Finally uncomment the `com.sap.cloud.security:java-api` dependency in the `pom.xml`.
 
When your code compiles again you should first check that all your unit tests are running again. If you can test your application locally make sure that it is still working and finally test the application with the new SAP Java Buildpack version in cloud foundry.

## Additional Hints
### UserInfoHolder
It is also still possible to use the `UserInfoHolder` to obtain the `XSUserInfo` object.

> We recommend to use the `SecurityContext` instead of `UserInfoHolder` as described in the [next section](#security-context).

### New Feature: SecurityContext <a name="security-context"></a>
In order to obtain token information from the thread local storage (instead of the request) you can use `SecurityContext` from [`java-api`](#maven).

```java
import com.sap.cloud.security.token.*;

AccessToken accessToken = SecurityContext.getAccessToken();
```
> Of course you can also leverage the `XSUserInfoAdapter` as explained [here](#xs-user).

### New Feature: SAP Java Buildpack without application roles
In case you are not interested in Authorization checks with application specific roles in your J2EE application, this is now possible. You can just disable local scopes as authorities in the buildpack via the system environment variable `DISABLE_LOCAL_SCOPE_AS_AUTHORITIES. By default it is set to `false`. If it is set to true, then the scopes/role check will not be performed on the local scopes but on the original scopes which are part of the `scope` claim of the token, such as "openid".

```java
@WebServlet(HelloJavaServlet.ENDPOINT)
@ServletSecurity(@HttpConstraint(rolesAllowed = { "openid" }))
public class HelloJavaServlet extends HttpServlet {
    ...
}
```

## Sample (TODO)
- [J2EE java web servlet sample using SAP Java Buildpack](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/samples/sap-java-buildpack-api-usage)

## Further References
- [help.sap.com](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/ead7ee64f96f4c42bacbf0ae23d4135b.html)
- [(SAP-internal) api versions provided with the buildpack](https://wiki.wdf.sap.corp/wiki/display/xs2java/Component+Versions)