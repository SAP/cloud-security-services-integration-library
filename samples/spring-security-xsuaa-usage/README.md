# Description
This sample uses the SAP Approuter as web server and forwards requests to a Java Spring backend application running on the CF community Java buildpack.
In a typcal UI5 application, the approuter would server HTML files and REST data would be provided by a backend application. To focus on the security part, UI5 has been omitted.

# Coding
This sample is using the spring-security project. As of version 5 of spring-security, this includes the OAuth resource-server functionality.The security configuration needs to configure JWT for authentication.




Configure the OAuth resource server by:
- setting the property source to integrate with xsuaa configuration properties
- adding a bean for the configuration
- using the xsuaa token converter
- configuring  the jwtDecoder

```
@EnableWebSecurity
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	XsuaaServiceConfigurationDefault xsuaaServiceConfiguration;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.authorizeRequests().
				antMatchers("/hello-token/**").hasAuthority("openid")
				.anyRequest().authenticated().
				and()
				.oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(new TokenAuthenticationConverter(xsuaaServiceConfiguration));
		// @formatter:on
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
- Download the approuter
- Compile the Java application
- Create a xsuaa service instance
- Configure the manifest
- Deploy the application
- Access the application
## Download the approuter
The [Application Router](./approuter/package.json) is used to provide a single entry point to a business application that consists of several different apps (microservices). It dispatches requests to backend microservices and acts as a reverse proxy. The rules that determine which request should be forwarded to which _destinations_ are called _routes_. The application router can be configured to authenticate the users and propagate the user information. Finally, the application router can serve static content.

## Compile the Java application
Run maven to package the application
```shell
    spring-security-xsuaa-usage$ mvn package
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
    spring-security-xsuaa-usage$ cf push --vars-file ../vars.yml
```

## Access the application
After deployment, the application router will trigger authentication. If you have assigned the role provided in the xs-security.json to your user, you will see an output like:
```
{
client id: "sb-spring-security-xsuaa-usage!t291",
family name: "Jones",
given name: "Bill",
subaccount id: "2f047cc0-4364-4d8b-ae70-b8bd39d15bf0",
logon name: "bill.jones@mail.com",
email: "bill.jones@mail.com",
grant type: "authorization_code",
token: "eyJhb..."
}
```


