# Migration Guide for Applications that use SAP Java Buildpack and java-container-security

**This document is only applicable as soon as the integration of this security library into the buildpack as been finished!**
This migration document is a step-by-step guide explaining how to migrate existing buildpack applications
that make use of java-container-security-api to the new security api.

## Prerequisite

**Please note, this Migration Guide is only intended for applications using SAP Java Buildpack.**
You're using the SAP Java Buildpack, if you can find the `sap_java_buildpack` in the deployment descriptor of your application, e.g. in your `manifest.yml` file.

## Overview of all breaking changes

The following list is an overview of the breaking changes that might require changes in existing
applications.

- New security related maven dependencies, see [Migration section](#migrate).
- `AccessToken` instead of `XSUserInfo` in tomcat principal object. See [User principal](#user-principal).
- Principal name is in new format, see [Principal name](#principal-name).

## Migrate an existing buildpack java app <a name="migrate"></a>

Your buildpack application has probably a dependency to one of the old security api projects in its `pom.xml`:

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>java-container-security-api</artifactId>
    <scope>provided</scope>
</dependency>
```

Or

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>api</artifactId>
    <scope>provided</scope>
</dependency>
```

> If you do not have any of the api projects above as dependency you can skip this chapter!

Those must be replaced with the new api project:

```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-api</artifactId>
    <version>2.6.0</version>
    <scope>provided</scope>
</dependency>
```

> Scope can be set to provided because it is already shipped with the buildpack.
> Take a look at the [version overview](https://wiki.wdf.sap.corp/wiki/display/xs2java/Component+Versions)
> to see which version of the api is provided with the buildpack.

Now you will most likely have compile error at places where the old api module was used. Those are the parts of the
application where information from the token (or user info) was read. See the next sections on how to migrate that.

## User principal <a name="user-principal"></a>

In the old version of the buildpack the user principal could be obtained via:

```java
XSUserInfo userInfo = (XSUserInfo) request.getUserPrincipal();
```

This is not possible anymore because getUserPrincipal does not return a `XSUserInfo` anymore. Instead it returns an
`com.sap.cloud.security.token.AccessToken` object. So you can cast it to `AccessToken`:

```java
AccessToken accessToken = (AccessToken) request.getUserPrincipal();
```

The data contained in the `AccessToken` is quite similar to `XSUserInfo`, but it is accessed differently. See a
detailed explanation in the [AccessToken vs XSUserInfo section](#access-token).

## AccessToken <a name="access-token"></a>

Depending on your usage of `XSUserInfo` the transition to `AccessToken` will be easy.
There are however some (legacy) methods that `AccessToken` does not implement.
The following table lists those methods that are not provided by `AccessToken`:

- `getDBToken()`
- `getHdbToken()`
- `getHdbToken()`
- `getToken(namespace, name)`
- `getAttribute(attributeName)`
- `hasAttributes()`
- `getSystemAttribute(attributeName)`
- `getCloneServiceInstanceId()`
- `isInForeignMode()`

If you require any of those methods you can use the `XSUserInfoAdapter`. See the
[XSUserInfoAdapter](#xs-userinfo-adapter) section for more details. If you do not need the methods listed above, you
can use the `AccessToken` directly. See the section [AccessToken vs XSUserInfo](#access-token-vs-xsuser-info) for
more details.

### AccessToken vs XSUserInfo <a name="access-token-vs-xsuser-info"></a>

The the following table shows a detailed comparison between `AccessToken` and `XSUserInfo`.

Note that the getter methods of the `AccessToken` do **not throw UserInfoException** in case the requested data is
not available. They will return `null` to show the absence of data.

| UserInfo method          | Replacement                | Note                      |
|--------------------------|----------------------------|---------------------------|
| `getLogonName()` | `token.getClaimAsString(TokenClaims.USER_NAME)` or `token.getPrincipal()` | `getPrincipal` returns something different, see [Principal name](#principal-name) |
| `getGivenName()` | `token.getClaimAsString(TokenClaims.GIVEN_NAME)` | Only if it is not an external attribute, see [External attribute with fallback](#external-attributes-fallback) |
| `getFamilyName()` | `token.getClaimAsString(TokenClaims.FAMILY_NAME)` | Only if it is not an external attribute, see [External attribute with fallback](#external-attributes-fallback) |
| `getOrigin()` | `token.getClaimAsString(TokenClaims.XSUAA.ORIGIN)` |
| `getIdentityZone()` | `token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)` |
| `getSubaccountId()` | `token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)` |
| `getSubdomain()` | Needs to be extracted from external attribute 'zdn' | See [External attributes](#external-attributes) or use [XSUserInfoAdapter](#xs-userinfo-adapter) |
| `getClientId()` | `token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)` |
| `getJsonValue(attribute)` | `token.getClaimAsString(attribute)` |
| `getEmail()` | `token.getClaimAsString(TokenClaims.EMAIL)` |
| `getAppToken()` | `token.getAccessToken()` |
| `checkScope(scope)` | `token.hasScope(scope)` |
| `checkLocalScope(scope)` | `token.hasLocalScope(scope)` |
| `getAdditionalAuthAttribute(attributeName)` | Use [XSUserInfoAdapter](#xs-userinfo-adapter)  |
| `getGrantType()` | `token.getGrantType()` |
| `requestTokenForClient(clientId, clientSecret, uaaUrl)` | Not supported |
| `requestToken(XSTokenRequest tokenRequest)` | Not supported |

### Principal name <a name="principal-name"></a>

The `Token` interface defines the `getPrincipal()` method that returns a `java.security.Principal` which provides a
`getName()` method.  If the underlying token is a xsuaa token then this will return `user/<origin>/<logonName>` if it is
a user token or `client/<clientid>` if it is a client credentials or X509 token. It does not return the static string
'client_credentials_principal_name' anymore.

### External attributes <a name="external-attributes"></a>

The external attributes is a special claim of a XSUAA token that contains several attributes. It can be obtained like
this:

```java
JsonObject externalAttributes = token.getClaimAsJsonObject(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE);
```

You can then obtain the attributes from this object, e.g.:

```java
String subdomain = externalAttributes.getAsString("zdn");
```

### External attribute with fallback <a name="external-attributes-fallback"></a>

In the java-container-security library the data was looked up for some attributes in the external attributes first
and then it fell back to extracting the data directly from the claims. This mechanism is not supported anymore. Data
in the external attributes is not treated special. If this mechanism is needed you can either implement like in the
following example...

```java
JsonObject externalAttributes = token.getClaimAsJsonObject(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE);
String attributeValue = externalAttributes.getAsString("attributeName");
if (attributeValue == null) {
  attributeValue = token.getClaimAsString("attributeName");
}
```

...or you can use the `XSUserInfoAdapter` that implements this mechanism and behaves like the java-container-security
library in this regard. See section [XSUserInfoAdapter](#xs-userinfo-adapter) for more details.

### XSUserInfoAdapter <a name="xs-userinfo-adapter"></a>

The `XSUserInfoAdapter` class is a wrapper for `Token` that implements the `XSUserInfo` interface and provides the
functionality that was implemented in the java-container-security library.  It is part of the java-security module and
needs to be added to your project as a dependency. You also need the legacy api project that contains the `XSUserInfo`
interface.

```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-security</artifactId>
</dependency>
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>api</artifactId>
</dependency>
```

Create a new instance of the adapter by passing the access token like so:

```java
XSUserInfo userInfo = new XSUserInfoAdapter(accessToken);
```

When using java-security in conjunction with the buildpack see section [java-security](#java-security) to avoid classpath issues.

## SecurityContext <a name="security-context"></a>

To obtain token information from the thread local storage you can use `SecurityContext` from [`java-api`](#migrate).

```java
import com.sap.cloud.security.token.*;

AccessToken token = SecurityContext.getAccessToken();
```

### UserInfoHolder
It is also still possible to use the `UserInfoHolder` to obtain the `UserInfo` object.

The difference between XSUserInfo and AccessToken is described in section [Access token](#access-token).

## General buildpack usage information

### Usage in combination with java-security <a name="java-security"></a>

If you use `java-security` in your application and deploy it via the SAP Java buildpack, you will need to exclude the
`slf4j-api` dependency of `java-security` to avoid classpath issues. This is because the buildpack provides its own
version of `slf4j-api`.

```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-security</artifactId>
    <exclusions>
        <exclusion>
            <artifactId>slf4j-api</artifactId>
            <groupId>org.slf4j</groupId>
        </exclusion>
    </exclusions>
</dependency>
```

### Disable local scopes as authorities

It is now possible to disable local scopes as authorities in the buildpack via the system environment variable
DISABLE_LOCAL_SCOPE_AS_AUTHORITIES. By default it is set to `false`. If it is set to true, then the scopes/role check
will not be performed on the local scopes but on the original scopes which are part of the `scope` claim of
the token.

## Sample
- [J2EE java web servlet sample using SAP Java Buildpack](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/samples/sap-java-buildpack-api-usage)

## Further References
- [help.sap.com](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/ead7ee64f96f4c42bacbf0ae23d4135b.html)
