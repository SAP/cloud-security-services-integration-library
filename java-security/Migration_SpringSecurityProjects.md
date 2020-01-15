
# Dependencies

## Maven
To use the new [java client lib](https://github.com/SAP/cloud-security-xsuaa-integration/) the dependencies declared in maven `pom.xml` need to be updated.

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
    <groupId>com.sap.cloud.security.xsuaa</groupId>
	<artifactId>java-security</artifactId>
	<version>2.4.0-SNAPSHOT</version>
</dependency>
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>java-security-test</artifactId>
  <version>2.4.0-SNAPSHOT</version>
  <scope>test</scope>
</dependency>
```

Also ensure that you do not use outdated versions of maven plugins that might affect your build. 
So for example if you use `findbugs-maven-plugin` or `jacoco-maven-plugin`, update them to a current version.

Now you are ready to **remove** the old client library by deleting the following lines from the pom.xml:
```xml
<dependency>
  <groupId>com.sap.xs2.security</groupId>
	<artifactId>java-container-security</artifactId>
</dependency>
```
<!-- Also remove the org.springframework.amqp:spring-rabbit dependency -->

## Update App router
The  from the app router needs to be updated as well. Find the `package.json` file inside 
`src/main/approuter` directory and replace the content with the following:
```json
{
  "name": "approuter",
  "dependencies": {
     "@sap/approuter": "6.1.0"
   },
   "scripts": {
     "start": "node node_modules/@sap/approuter/approuter.js"
    }
}
```

## Update build packs
Find the `manifest.yml` in the root directory.

Update the `java-buildpack` to version `v4.27`.
and the nodejs buildpack to version `v1.6.49`.

# Code changes
After the dependencies have been changed, the project code probably needs some adjustments as well.

If your security configuration was using the `SAPOfflineTokenServicesCloud` class from the java-container-security library,
you need to change it slightly to use the `SAPOfflineTokenServicesCloud` adapter class from the new library.  

For example see the following snippet on how to instantiate the `SAPOfflineTokenServicesCloud`. 

```java
    @Bean
    @Profile("cloud")
    protected SAPOfflineTokenServicesCloud offlineTokenServices() {
        return new SAPOfflineTokenServicesCloud(Environments.getCurrent().getXsuaaConfiguration());
    }
```
You might need to fix your java imports to get rid of the old import for the `SAPOfflineTokenServicesCloud` class.


## Repair tests
The `src/test/java/com/sap/bulletinboard/ads/testutils/JwtGenerator.java` class must be removed because the new java
client test library provides it's own `JwtGenerator`.

### Security configuration for tests
If you want to overwrite the service configuration of the `SAPOfflineTokenServicesCloud` for your test, you can do so by
using some test constants provided by the test library. The following snippet shows how to do that:
```java 
@Configuration
public class TestSecurityConfig {
	@Bean
	@Primary
	public SAPOfflineTokenServicesCloud sapOfflineTokenServices() {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withClientId(SecurityTestRule.DEFAULT_CLIENT_ID)
				.withProperty(CFConstants.XSUAA.APP_ID, SecurityTestRule.DEFAULT_APP_ID)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, SecurityTestRule.DEFAULT_DOMAIN) //TODO
				.build();
		return new SAPOfflineTokenServicesCloud(configuration);
	}
}
```

### Unit testing 
In your unit test you might want to generate jwt tokens and have them validated. This can be done with the new 
`SecurityTestRule`. See the following snippet as example: 

```java
    @ClassRule
    public static SecurityTestRule securityTestRule =
            SecurityTestRule.getInstance(Service.XSUAA)
                    .setKeys("src/test/resources/publicKey.txt", "src/test/resources/privateKey.txt");
```

Using the SecurityTestRule you can use a preconfigured jwt generator to create JWT tokens with custom scopes for your tests.

```java
String jwt = securityTestRule.getPreconfiguredJwtGenerator()
    .withScopes(WebSecurityConfig.DISPLAY_SCOPE, WebSecurityConfig.UPDATE_SCOPE)
    .createToken()
    .getBearerAccessToken();

```

<!-- 
Remove the following files:
CloudRabbitConfig.java
StatisticsListener.java
MockRabbitConfig.java
StatisticsServiceClient.java

In `SpringBootActuatorConfig` remove the `RabbitAutoConfiguration.class` autoconfiguration.

In `AdvertisementController` remove the 
`StatisticsServiceClient` injection, the field and all the field usages.
-->

# Enable local testing
For local testing you might need to provide custom `VCAP_SERVICES` before you run the application. 
The new security library requires the key value pair `"uaadomain" : "localhost"` in the `VCAP_SERVICES`
under `xsuaa/credentials` to be able to validate the XSUAA tokens.

# Things to check after migration 
When your code compiles again you should first check that all your unit tests are running again. If you can test your
application locally make sure that it is still working and finally test the application in cloud foundry.
