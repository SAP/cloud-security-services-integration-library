# Description
In some situations, the client does not support OAuth protocols so you need to fall back to basic authentication. This sample uses a implementation of the [bearerTokenResolver](https://docs.spring.io/spring-security/site/docs/5.1.1.RELEASE/api/org/springframework/security/oauth2/server/resource/web/BearerTokenResolver.html). Depending on the configuration, this resolver will
- Support OAuth JWT tokens
- exchange incoming credentials using the OAuth password grant flow
- exchange incoming credentials using the OAuth client credential flow

Note: OAuth JWT tokens can be combined with either password grant or client credential flow.

# Coding
This sample is using the spring-security project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. The security configuration needs to configure JWT for authentication.




Configure the OAuth resource server by:
- Enable caching to avoid requesting new tokens for every call
- setting the property source to integrate with xsuaa configuration properties
- adding a bean for the configuration
- using the xsuaa token converter
- configuring the jwtDecoder
- enable the bearerTokenResolver

```
@EnableWebSecurity
@EnableCaching
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	XsuaaServiceConfigurationDefault xsuaaServiceConfiguration;

	@Autowired
	CacheManager cacheManager;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		TokenBrokerResolver tokenBrokerResolver = new TokenBrokerResolver(xsuaaServiceConfiguration, cacheManager.getCache("token"),AuthenticationMethod.BASIC);
		http.authorizeRequests().antMatchers("/hello-token").hasAuthority("openid").
		anyRequest().authenticated().and()
				.oauth2ResourceServer()
				  .bearerTokenResolver(tokenBrokerResolver)
				.jwt()
				  .jwtAuthenticationConverter(new TokenAuthenticationConverter(xsuaaServiceConfiguration));
	}

	@Bean
	JwtDecoder jwtDecoder() {
		return new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration).build();
	}

	@Bean
	XsuaaServiceConfigurationDefault config() {
		return new XsuaaServiceConfigurationDefault();
	}
}
```

In the Java coding, use the `Token` to extract user information:

```
	@GetMapping("/hello-token")
	public Map<String, String> message(@AuthenticationPrincipal Token token) {
		Map<String, String> result = new HashMap<>();
		result.put("grant type", token.getGrantType());
		result.put("client id", token.getClientId());
		result.put("subaccount id", token.getSubaccountId());
		result.put("logon name", token.getLogonName());
		result.put("family name", token.getFamilyName());
		result.put("given name", token.getGivenName());
		result.put("email", token.getEmail());
		result.put("token", token.getAppToken());

		return result;
	}
```
# Deployment on Cloud Foundry or SAP HANA Advanced
To deploy the application, the following steps are required:
- Compile the Java application
- Create a xsuaa service instance
- Configure the manifest
- Deploy the application
- Access the application

## Compile the Java application
Run maven to package the application
```shell
    spring-security-basic-auth$ mvn package
```
## Create the xsuaa service instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a service instance
```shell
    spring-security-xsuaa-usage$ cf create-service xsuaa application xsuaa-authentication -c xs-security.json
```
## Configuration the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
    spring-security-basic-auth$ cf push --vars-file ../vars.yml
```

## Access the application
After deployment, the spring service can be called with basic authentication.
```
curl -i --user "<SAP ID Service User>:<SAP ID Service Password>" https://spring-security-basic-auth-00-00-00.cfapps.eu10.hana.ondemand.com/hello-token

{
  "client id": "sb-spring-security-xsuaa-usage!t291",
  "family name": "Jones",
  "given name": "Bob",
  "subaccount id": "2f047cc0-4364-4d8b-ae70-b8bd39d15bf0",
  "logon name": "bob.jones@example.com",
  "email": "bob.jones@example.com",
  "grant type": "password",
  "token": "ey..."
}
```


