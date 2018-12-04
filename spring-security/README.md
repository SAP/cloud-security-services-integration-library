# XSUAA Security 

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

## Support Spring EnableOAuth2Sso-Annotation

Reading sso relevant variables from VCAP SERVICES and injecting into properties values. So the user can enable OAuth2-SSO just by using the EnableOAuth2Sso annotation.

* **security.oauth2.client.clientId**: The OAuth client id. This is the id by which the OAuth provider identifies your client.  
* **security.oauth2.resource.prefer-token-info**: Use the token info, can be set to false to use the user info.
* **security.oauth2.resource.user-info-uri**: URI of the user endpoint.
* **security.oauth2.client.userAuthorizationUri**: The uri to which the user will be redirected if the user is ever needed to authorize access to the resource. Note that this is not always required, depending on which OAuth 2 profiles are supported.
* **security.oauth2.client.accessTokenUri**: The URI of the provider OAuth endpoint that provides the access token.
* **security.oauth2.client.clientSecret**:  The secret associated with the resource. By default, no secret is empty.

### Usage

```java
@Configuration
@EnableOAuth2Sso
public class SecurityConfig extends WebSecurityConfigurerAdapter {
     
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**")
          .authorizeRequests()
          .antMatchers("/", "/login**")
          .permitAll()
          .anyRequest()
          .authenticated();
    }
}
```

## Authentication via basic authorization header

Sending Basic or Client Credentials as basic authorization header and retrieve a token by using a password or credential grant from against the UAA.

### Usage

```java
@RestController
@EnableWebMvc
@Configuration
public class TokenExtractorController {

	@Autowired
	private XsuaaConfiguration configuration;

	@Autowired
	private Cache tokenCache;

	@Autowired
	private TokenBroker tokenBroker;

	@Autowired
	private AuthenticationInformationExtractor authenticationConfiguration;

	@Bean
	public CredentialExtractor basicCredentialExtractor() {
		return new CredentialExtractor(configuration, tokenCache, tokenBroker, authenticationConfiguration);
	}

	@GetMapping("/basic/token/extractor")
	public ResponseEntity<?> basicTokenExtractor(HttpServletRequest request) {
		Authentication authentication = basicCredentialExtractor().extract(request);
		return ResponseEntity.ok().body(authentication.getPrincipal());
	}

}
```

For using this feature also in multi tenancy mode request-parameter **X-Identity-Zone-Subdomain** must be set.