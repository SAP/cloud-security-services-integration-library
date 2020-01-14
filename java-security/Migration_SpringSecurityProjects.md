
# Dependencies

## Maven
To use the new [java client lib](https://github.com/SAP/cloud-security-xsuaa-integration/) the dependencies declared in maven `pom.xml` need to be updated.

First add the following dependencies:
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
Also two maven plugins need to be updated. First update `findbugs-maven-plugin` to version `3.0.5` and then update `jacoco-maven-plugin` to version `0.8.2`.

Now **remove** the old client library by deleting the following lines from the pom.xml:
```xml
<dependency>
    <groupId>com.sap.xs2.security</groupId>
	<artifactId>java-container-security</artifactId>
	<version>0.27.2</version>
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
After the dependencies have been changed, the project code needs some adjustments as well.

## Provide SAPOfflineTokenServicesCloud
In `src/main/java/com/sap/bulletinboard/ads/config/WebSecurityConfig.java` the `SAPOfflineTokenServicesCloud` cannot be found anymore. This class neeeds to be implemented first. Create the new file `src/main/java/com/sap/bulletinboard/ads/services/SAPOfflineTokenServicesCloud.java` and paste the following content:
```java
package com.sap.bulletinboard.ads.services;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class SAPOfflineTokenServicesCloud implements ResourceServerTokenServices, InitializingBean {

	private CombiningValidator<Token> tokenValidator;
	private OAuth2ServiceConfiguration serviceConfiguration;

	public SAPOfflineTokenServicesCloud(OAuth2ServiceConfiguration serviceConfiguration) {
		this.serviceConfiguration = serviceConfiguration;
	}

	@Override
	public OAuth2Authentication loadAuthentication(String accessToken)
			throws AuthenticationException, InvalidTokenException {
		XsuaaToken token = new XsuaaToken(accessToken);
		Set<String> scopes = token.getScopes().stream().collect(Collectors.toSet());

		AuthorizationRequest authorizationRequest = new AuthorizationRequest(new HashMap<>(), null,
				serviceConfiguration.getClientId(), scopes, new HashSet<>(), null,
				tokenValidator.validate(token).isValid(), "", "", null);

		return new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);
	}

	@Override
	public void afterPropertiesSet() {
		tokenValidator = JwtValidatorBuilder.getInstance(serviceConfiguration).build();
	}

	@Override public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}
}
```
Now the `WebSecurityConfig.java` needs some slight modifications to use the newly created class. The `SAPOfflineTokenServicesCloud` bean now needs to be declared like this. Note the additional `@Profile` annotation. It is necessary so that the bean is not created when running unit tests.

```java
    @Bean
    @Profile("cloud")
    protected SAPOfflineTokenServicesCloud offlineTokenServices() {
        return new SAPOfflineTokenServicesCloud(Environments.getCurrent().getXsuaaConfiguration());
    }
```

## Repair unit tests
The `src/test/java/com/sap/bulletinboard/ads/testutils/JwtGenerator.java` class must be removed because the new java client test library provides it's own `JwtGenerator`.

### TestSecurityConfig
The `src/test/java/com/sap/bulletinboard/ads/config/TestSecurityConfig.java` needs to be changed. Just replace the content of the file with the following snippet: 
```java 
package com.sap.bulletinboard.ads.config;

import com.sap.bulletinboard.ads.services.SAPOfflineTokenServicesCloud;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.test.SecurityTestRule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class TestSecurityConfig {
	@Bean
	@Primary
	public SAPOfflineTokenServicesCloud sapOfflineTokenServices() {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withClientId(SecurityTestRule.DEFAULT_CLIENT_ID)
				.withProperty(CFConstants.XSUAA.APP_ID, SecurityTestRule.DEFAULT_APP_ID)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "localhost")
				.build();
		return new SAPOfflineTokenServicesCloud(configuration);
	}
}
```

### AdvertisementControllerTest

First add a new rule to the test by adding the following line: 
```java
@ClassRule
    public static SecurityTestRule securityTestRule = SecurityTestRule.getInstance(Service.XSUAA)
            .setKeys(RSAKeys.generate());
```

> Note that the unit test uses random RSA keys for testing. To use a static set of RSA keys you can create an `RSAKeys` object with `RSAKeys.fromKeyFiles()` and pass that to the 
`securityTestRule`.

<!-- 
	static {
		try {
			keys = RSAKeys.fromKeyFiles("src/test/resources/publicKey.txt", "src/test/resources/privateKey.txt");
		} catch (Exception e) {
            throw new RuntimeException(e);
		}
	}
    @ClassRule
    public static SecurityTestRule securityTestRule = SecurityTestRule.getInstance(Service.XSUAA).setKeys(keys);
-->

Now the jwt initialization in the `setUp` method must be changed:

```java
jwt = securityTestRule.getPreconfiguredJwtGenerator()
    .withScopes(WebSecurityConfig.DISPLAY_SCOPE, WebSecurityConfig.UPDATE_SCOPE)
    .createToken()
    .getBearerAccessToken();

```
The nit test case `createForbiddenWithoutUpdateScope` generates a custom jwt token. To make this work change the first line of the test case to the following: 

```java
String jwtReadOnly = securityTestRule.getPreconfiguredJwtGenerator()
    .withScopes(WebSecurityConfig.DISPLAY_SCOPE)
    .createToken()
    .getBearerAccessToken();
```

Now all the unit tests should run again. You might need to fix some java imports though.


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

## Enable local testing
In `localEnvironmentSetup.sh` in the root directory add the key value pair `"uaadomain":"localhost"` to `VCAP_SERVICES` under `xsuaa/credentials`.
