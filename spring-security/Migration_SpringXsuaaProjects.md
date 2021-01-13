# UNDER CONSTRUCTION 
# Migration Guide for Applications that use spring-xsuaa Security Client Library

This migration guide is a step-by-step guide explaining how to replace the [`spring-xsuaa`](/spring-xsuaa) with this ``spring-security``(/spring-security) Security client library.

## Maven Dependencies
To use the new SAP CP [spring-security](/spring-security) client library the dependencies declared in maven `pom.xml` need to be updated.

Make sure, that you add the dependencies that are documented [here](/spring-security#maven-dependencies).

Now you are ready to **remove** the **`spring-xsuaa`** client library by deleting the following dependencies from the `pom.xml`:

groupId (deprecated) | artifactId (deprecated) 
--- | --- 
com.sap.cloud.security.xsuaa | spring-xsuaa
com.sap.cloud.security.xsuaa | xsuaa-spring-boot-starter


## Configuration changes
After the dependencies have been changed, the spring security configuration needs some adjustments as well.

This means that you have to adapt the `HttpSecurity` configuration. This involves the following steps:

TODO


### Access VCAP_SERVICES values
There are two options to access information of the identity service instance (`VCAP_SERVICES` credentials):

TODO


## Fetch data from token

### `Token` methods
The `com.sap.cloud.security.xsuaa.token.Token` interface from `spring-xsuaa` provides some special methods that are not available in
the `com.sap.cloud.security.token.Token` interface from `spring-security`.

See the following table for methods that are not available in ```Token``` interface. The ```Token``` interface is the common interface for tokens issued by both of the identity services. There are two sub-interfaces: 
- ```AccessToken``` interface in case of access token issued by the xsuaa service, or 
- ```SapIdToken``` interface in case of oidc token issued by the identity service.


| `com.sap.cloud.security.xsuaa.token.Token` methods       | Workaround in `spring.security` (`com.sap.cloud.security.token.Token)                                                                                      |
|-------------------------|--------------------------------------------------------------------------------------------------|
| `getSubaccountId`          | Available via `AccessToken` interface in case ```Service.XSUAA.equals(token.getService())```                                                                         |`
| `getSubdomain`          | Available via `XsuaaToken` implementation in case ```Service.XSUAA.equals(token.getService())``` 
| `getGrantType`          | Available via `AccessToken.getGrantType().toString()` interface in case ```Service.XSUAA.equals(token.getService())```   
| `getLogonName`            | `getPrincipal()getName()`. 
| `getOrigin`            | ```getClaimAsString(TokenClaims.ORIGIN)```.
| `getGivenName`          | ```getClaimAsString(TokenClaims.GIVEN_NAME)```. :bulb: no support for SAML 2.0 - XSUAA mapping.
| `getFamilyName`          | ``getClaimAsString(TokenClaims.FAMILY_NAME)``. :bulb: no support for SAML 2.0 - XSUAA mapping.
| `getEmail`          | ``getClaimAsString(TokenClaims.EMAIL)``. :bulb: no support for SAML 2.0 - XSUAA mapping.
| `getXSUserAttribute`          | Not implemented.
| `getAdditionalAuthAttribute`  | Not implemented.
| `getCloneServiceInstanceId`  | Not implemented.
| `getAppToken`  | use `getTokenValue`
| `getScopes`  | use `getClaimAsStringList(TokenClaims.XSUAA.SCOPES)`
| `getAuthorities()`  | TODO
| `getExpiration()`  | use `isExpired()` and `getExpiration()` instead.

### Spring's `Jwt` methods

The runtime type of `com.sap.cloud.security.xsuaa.token.Token` is `com.sap.cloud.security.xsuaa.token.XsuaaToken`, which provides additional methods that can be used to extract data from the token since it is a subclass of
`org.springframework.security.oauth2.jwt.Jwt`. 

The following table gives an overview about the most prominent used ``Jwt`` methods and how they can be mapped:

|`org.springframework.security.oauth2.jwt.Jwt` methods       | Workaround in `spring.security` (using `com.sap.cloud.security.token.Token)                                                                                      |
|-------------------------|--------------------------------------------------------------------------------------------------|
| `getClaimAsString`       | `getClaimAsString` |
| `getClaimAsStringList`  | ` getClaimAsStringList` |
| `containsClaim`          | `hasClaim` |
| `getClaims`              | `getClaims` |
| `getHeaders`             | `getHeaders` |
| `getClaimAsInstant`      | `getClaimAsJsonObject().getAsInstant()` |


## Testing
In your unit test you might want to generate jwt tokens and have them validated. The new
[java-security-test](/java-security-test) library provides its own `JwtGenerator`. 

See the [java-security-test documentation](/java-security-test) for more details, also on how to leverage JUnit 5 extensions.

The new security library requires the following key value pairs to configure the jwt validators. You can use the defaults specified within the ``java-security-test`` testing library.

````yaml
xsuaa:
  xsappname: xsapp!t0815
  uaadomain: localhost
  clientid: sb-clientId!t0815
  url: http://localhost

identity:
  clientid: sb-clientId!t0815
  domain: localhost
````


## Things to check after migration 
When your code compiles again you should first check that all your unit tests are running again. If you can test your
application locally make sure it is still working and finally test the application in cloud foundry.


## Issues
In case you face issues to apply the migration steps check this [troubleshoot](README.md#troubleshoot) for known issues and how to file the issue.

## Samples
- [Sample](/samples/spring-security-hybrid-usage)    

## Further References
- [spring-security documentation](/spring-security/README.md)
