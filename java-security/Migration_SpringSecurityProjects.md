# Migration Guide for Applications that use Spring Security and java-container-security

This migration guide is a step-by-step guide explaining how to replace the following SAP-internal Java Container Security Client libraries
- com.sap.xs2.security:java-container-security
- com.sap.cloud.security.xsuaa:java-container-security  

with this open-source version.

## Maven Dependencies
To use the new [java-security](/java-security) client library the dependencies declared in maven `pom.xml` need to be updated.

First make sure you have the following dependencies defined in your pom.xml:

```xml
<-- updated spring-security dependencies -->
<dependency>
  <groupId>org.springframework.security.oauth</groupId>
  <artifactId>spring-security-oauth2</artifactId>
  <version>2.4.0.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-aop</artifactId>
  <version>4.3.25.RELEASE</version>
</dependency>

<-- new java-security dependencies -->
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>api</artifactId>
  <version>2.5.1</version>
</dependency>
<dependency>
  <groupId>com.sap.cloud.security</groupId>
  <artifactId>java-security</artifactId>
  <version>2.5.1</version>
</dependency>
<dependency>
  <groupId>com.sap.cloud.security</groupId>
  <artifactId>java-security-test</artifactId>
  <version>2.5.1</version>
  <scope>test</scope>
</dependency>
```


Now you are ready to **remove** the **`java-container-security`** client library by deleting the following lines from the pom.xml:
```xml
<dependency>
  <groupId>com.sap.xs2.security</groupId>
  <artifactId>java-container-security</artifactId>
</dependency>
```
Or
```xml
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>java-container-security</artifactId>
</dependency>
```

## Configuration changes
After the dependencies have been changed, the spring security configuration needs some adjustments as well.

If your security configuration was using the `SAPOfflineTokenServicesCloud` class from the `java-container-security` library,
you need to change it slightly to use the `SAPOfflineTokenServicesCloud` adapter class from the new library.

> Note: There is no replacement for `SAPPropertyPlaceholderConfigurer` as you can always parameterize the `SAPOfflineTokenServicesCloud` bean with your ``.

### Code-based

For example see the following snippet on how to instantiate the `SAPOfflineTokenServicesCloud`. 

```java
@Bean
@Profile("cloud")
protected SAPOfflineTokenServicesCloud offlineTokenServices() {
	return new SAPOfflineTokenServicesCloud(
				Environments.getCurrent().getXsuaaConfiguration(), //optional
				new RestTemplate())                                //optional
			.setLocalScopeAsAuthorities(true);                         //optional
}
```
You might need to fix your java imports to get rid of the old import for the `SAPOfflineTokenServicesCloud` class.

### XML-based
As you may have updated the 

In case of XML-based Spring (Security) configuration you need to replace your current `SAPOfflineTokenServicesCloud` bean definition with that:

```xml
<bean id="offlineTokenServices"
         class="com.sap.cloud.security.adapter.spring.SAPOfflineTokenServicesCloud">
		<property name="localScopeAsAuthorities" value="true" />
</bean>
```

With `localScopeAsAuthorities` you can perform spring scope checks without referring to the XS application name (application id), e.g. `myapp!t1234`. For example:

Or
```java
...
.authorizeRequests()
	.antMatchers(POST, "/api/v1/ads/**").access(#oauth2.hasScopeMatching('Update')) //instead of '${xs.appname}.Update'
```


```xml
<sec:intercept-url pattern="/rest/addressbook/deletedata" access="#oauth2.hasScope('Delete')" method="GET" />
```

## Fetch basic infos from Token
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

This can be easily replaced with the `Token` or `XsuaaToken` Api.

```java
import com.sap.cloud.security.token.*;

AccessToken token = SecurityContext.getAccessToken();
String logonName = token.getClaimAsString(TokenClaims.USER_NAME);
boolean hasDisplayScope = token.hasLocalScope("Display");	
GrantType grantType = token.getGrantType();
```

> Note, that no `XSUserInfoException` is raised, in case the token does not contain the requested claim.

## Fetch further `XSUserInfo` infos from Token
When you're done with the first part and need further information from the token you can use `XSUserInfoAdapter` in order to access the remaining methods exposed by [`XSUserInfo`](/api/src/main/java/com/sap/xsa/security/container/XSUserInfo.java) Interface.

```java
try {
	XSUserInfo userInfo = new XSUserInfoAdapter(token);
	String dbToken = userInfo.getHdbToken();
} catch (XSUserInfoException e) {
	// handle exception
}
```

## Test Code Changes

### Security configuration for tests
If you want to overwrite the service configuration of the `SAPOfflineTokenServicesCloud` for your test, you can do so by
using some test constants provided by the test library. The following snippet shows how to do that:
```java 
import static com.sap.cloud.security.config.cf.CFConstants.*;

@Configuration
public class TestSecurityConfig {
	@Bean
	@Primary
	public SAPOfflineTokenServicesCloud sapOfflineTokenServices() {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withClientId(SecurityTestRule.DEFAULT_CLIENT_ID)
				.withProperty(CFConstants.XSUAA.APP_ID, SecurityTestRule.DEFAULT_APP_ID)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, SecurityTestRule.DEFAULT_DOMAIN)
				.build();
		return new SAPOfflineTokenServicesCloud(configuration);
	}
}
```

### Unit testing 
In your unit test you might want to generate jwt tokens and have them validated. The new [java-security-test](/java-security-test) library provides it's own `JwtGenerator`.  This can be embedded using the new 
`SecurityTestRule`. See the following snippet as example: 

```java
@ClassRule
public static SecurityTestRule securityTestRule =
	SecurityTestRule.getInstance(Service.XSUAA)
		.setKeys("src/test/resources/publicKey.txt", "src/test/resources/privateKey.txt");
```

Using the `SecurityTestRule` you can use a preconfigured `JwtGenerator` to create JWT tokens with custom scopes for your tests. It configures the JwtGenerator in such a way that **it uses the public key from the [`publicKey.txt`](/java-security-test/src/main/resources) file to sign the token.**

```java
String jwt = securityTestRule.getPreconfiguredJwtGenerator()
    .withScopes(WebSecurityConfig.DISPLAY_SCOPE, WebSecurityConfig.UPDATE_SCOPE)
    .createToken()
    .getTokenValue();

```

Make sure, that your JUnit tests are running.

## Enable local testing
For local testing you might need to provide custom `VCAP_SERVICES` before you run the application. 
The new security library requires the following key value pairs in the `VCAP_SERVICES`
under `xsuaa/credentials` for jwt validation:
- `"uaadomain" : "localhost"`
- `"verificationkey" : "<public key your jwt token is signed with>"`

Before calling the service you need to provide a digitally signed JWT token to simulate that you are an authenticated user. 
- Therefore simply set a breakpoint in `JWTGenerator.createToken()` and run your `JUnit` tests to fetch the value of `jwt` from there. 

Now you can test the service manually in the browser using the `Postman` chrome plugin and check whether the secured functions can be accessed when providing a valid generated Jwt Token.


## Things to check after migration 
When your code compiles again you should first check that all your unit tests are running again. If you can test your
application locally make sure that it is still working and finally test the application in cloud foundry.

## Troubleshoot
- org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException: Line 51 in XML document from ServletContext resource [/WEB-INF/spring-security.xml] is invalid; nested exception is org.xml.sax.SAXParseException; lineNumber: 51; columnNumber: 118; cvc-complex-type.2.4.c: The matching wildcard is strict, but no declaration can be found for element 'oauth:resource-server'.
[Stackoverflow: no declaration can be found for element 'oauth:authorization-server'](https://stackoverflow.com/questions/32484988/the-matching-wildcard-is-strict-but-no-declaration-can-be-found-for-element-oa)

## Issues
In case you face issues to apply the migration steps feel free to open a Issue here on [Github.com](https://github.com/SAP/cloud-security-xsuaa-integration/issues/new).

