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

In case you have configured your `TokenAuthenticationConverter` with `setLocalScopeAsAuthorities(true)` then you can use the auto-configured converter instead as  documented [here](/spring-security#setup-spring-security-oauth-20-resource-server):
```
@Autowired
Converter<Jwt, AbstractAuthenticationToken> authConverter;
```

### Access VCAP_SERVICES values
`spring-security` does not automatically map all properties to Spring `xsuaa.*` properties. You can only access those properties via 

- `XsuaaServiceConfiguration` interface or
- `@Value("${xsuaa.clientid})` annotation

that you have mapped to your within your `application.yml` as explained [here](/spring-security#map-properties-to-vcap_services).


## Fetch data from token

### ``SpringSecurityContext``
You may have code parts that uses the `SpringSecurityContext` to get the token. Just update the import from:
````java
 import com.sap.cloud.security.xsuaa.token.SpringSecurityContext;
````
to
````java
import com.sap.cloud.security.token.SpringSecurityContext;
````

### `Token` methods
You may have code parts that uses the `Token` interface to access details from the token. You need to update the imports from:
````java
 import com.sap.cloud.security.xsuaa.token.Token;
````
to
````java
import com.sap.cloud.security.token.Token;
````

The ``Token`` interface from ``spring-security`` needs to provide methods that can be served by both kind of tokens. That's why they are not compatible.
It provides two sub-interfaces: 
- ```AccessToken``` interface in case of access token issued by the xsuaa service, or 
- ```SapIdToken``` interface in case of oidc token issued by the identity service.

See the following table for methods that are not available in the target ```Token``` interface. 

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
