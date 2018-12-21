# XSUAA Security 

## Integrate in a OAuth resource server

This library enhances the spring-security project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. A Spring boot application needs a security configuration class that enables the resource server and configures authentication using JWT tokens.

## Usage
Set the property source for xsuaa service binding on the application:

```
@SpringBootApplication
@ComponentScan(basePackageClasses=XsuaaServiceConfigurationDefault.class)
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
public class Application 
```

Configure the OAuth resource server

```
@EnableWebSecurity
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

}
```

In the Java coding, use the `Token` to extract user information:

```
	@GetMapping("/hello-token")
	public Map<String, String> message(@AuthenticationPrincipal Token token) {
```

## Inject VCAP-Service Properties 

Reading xsuaa variables from VCAP SERVICES and injecting into fields.

### Usage


```java
@Configuration
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
public class XsuaaConfiguration {

	public XsuaaConfiguration() {
	}

	@Value("${xsuaa.clientid:}")
	private String clientId;

	@Value("${xsuaa.clientsecret:}")
	private String clientSecret;

	@Value("${xsuaa.url:}")
	private String uaaUrl;

	@Value("${xsuaa.uaadomain:}")
	private String uaadomain;

}
```
