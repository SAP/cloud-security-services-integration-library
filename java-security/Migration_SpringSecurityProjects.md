# Migration Guide for Applications that use Spring Security and java-container-security

## Maven Dependencies
To use the new [java-security](/java-security) client library the dependencies declared in maven `pom.xml` need to be updated.

First make sure you have the following dependencies defined in your pom.xml:

```xml
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
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-web</artifactId>
    <version>5.2.3.RELEASE</version>
</dependency>
<-- new java-security dependencies -->
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>java-security</artifactId>
  <version>2.4.1-SNAPSHOT</version>
</dependency>
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>java-security-test</artifactId>
  <version>2.4.1-SNAPSHOT</version>
  <scope>test</scope>
</dependency>
```


Now you are ready to **remove** the old client library by deleting the following lines from the pom.xml:
```xml
<dependency>
  <groupId>com.sap.xs2.security</groupId>
  <artifactId>java-container-security</artifactId>
</dependency>
```

## Code changes
After the dependencies have been changed, the project code probably needs some adjustments as well.

If your security configuration was using the `SAPOfflineTokenServicesCloud` class from the `java-container-security` library,
you need to change it slightly to use the `SAPOfflineTokenServicesCloud` adapter class from the new library.  

For example see the following snippet on how to instantiate the `SAPOfflineTokenServicesCloud`. 

```java
@Bean
@Profile("cloud")
protected SAPOfflineTokenServicesCloud offlineTokenServices() {
	return new SAPOfflineTokenServicesCloud(Environments.getCurrent().getXsuaaConfiguration(), new RestTemplate());
}
```
You might need to fix your java imports to get rid of the old import for the `SAPOfflineTokenServicesCloud` class.


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
    .getBearerAccessToken();

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


