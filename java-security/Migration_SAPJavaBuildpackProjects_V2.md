# Migration Guide for J2EE Web Applications that use SAP Java Buildpack for securing their applications


**This document is only applicable for J2EE web applications securing their application with SAP Java Buildpack.** 

This migration document is a step-by-step guide explaining how to leverage the new api that is exposed by the SAP Java Buildpack as of version `1.26.1`.

## Prerequisites

Please note, this Migration Guide is only intended for applications, using SAP Java Buildpack. You're using the SAP Java Buildpack if you can find the `sap_java_buildpack` in the deployment descriptor of your application, e.g. in your `manifest.yml` file.

Furthermore [this guide](Migration_SAPJavaBuildpackProjects.md) is considered as prerequisite. Before you proceed, make sure you have completed it first.

## Adapt Maven Dependencies <a name="maven"></a>
To use the latest API exposed by SAP Java Buildpack version as of version `1.26.1` the dependency declared in maven `pom.xml` needs to be adapted.

First make sure you have the following dependency defined in your pom.xml:
```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-api</artifactId>
    <version>2.7.2</version>
    <scope>provided</scope> <!-- provided with buildpack -->
</dependency>
```

Now you are ready to **remove** the dependency to the **`api`** by deleting the following lines from the pom.xml:
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>api</artifactId>
    <version>2.7.2</version>
    <scope>provided</scope>
</dependency>
```
The dependency `com.sap.cloud.security:java-api` is the new api exposed by the SAP Java Buildpack as of version `1.26.1`.

## Adapt Environment Variable
As the new `java-api` is incompatible with the former one, you have to tell the SAP Java Buildpack, that you want to use the latest api. This is done by setting the `ENABLE_SECURITY_JAVA_API_V2` environment variable to `true` as part of your deployment descriptor, e.g. in your `manifest.yml` file.

With that the SAP Java Buildpack will provide `com.sap.cloud.security.token.AccessToken` instead of `XSUserInfo` in tomcat principal object. 

```java
AccessToken userInfo = (AccessToken) request.getUserPrincipal();
```


## Additional Hints
### UserInfoHolder
It is also still possible to use the `UserInfoHolder` to obtain the `XSUserInfo` object. This would require a dependency to `com.sap.cloud.security.xsuaa:api`.


### New Feature: SecurityContext <a name="security-context"></a>
In order to obtain token information from the thread local storage (instead of the request) you can use `SecurityContext` from [`java-api`](#maven).

```java
import com.sap.cloud.security.token.*;

AccessToken accessToken = SecurityContext.getAccessToken();
```


### New Feature: SAP Java Buildpack without application roles
In case you are not interested in Authorization checks with application specific roles in your J2EE application, this is now possible. You can just disable local scopes as authorities in the buildpack via the system environment variable `DISABLE_LOCAL_SCOPE_AS_AUTHORITIES`. By default it is set to `false`. If it is set to `true`, then the scopes/role check will not be performed on the local scopes but on the original scopes which are part of the `scope` claim of the token, such as "openid".

```java
@WebServlet(HelloJavaServlet.ENDPOINT)
@ServletSecurity(@HttpConstraint(rolesAllowed = { "openid" }))
public class HelloJavaServlet extends HttpServlet {
    ...
}
```

### Sample using new API
- [J2EE java web servlet sample using SAP Java Buildpack](https://github.com/SAP/cloud-security-xsuaa-integration/tree/UpdatedBuildpackSample/samples/sap-java-buildpack-api-usage)

## Further References
- [help.sap.com](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/ead7ee64f96f4c42bacbf0ae23d4135b.html)


