package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.SpringOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.SpringOidcConfigurationService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This constructor requires a dependency to Spring-security oauth, which will
 * be deprecated soon.
 *
 * <pre>
 * {@code
 * <dependency>
 *     <groupId>org.springframework.security.oauth</groupId>
 *     <artifactId>spring-security-oauth2</artifactId>
 *     <scope>provided</scope>
 * </dependency>
 * <dependency>
 *     <groupId>org.springframework</groupId>
 *     <artifactId>spring-beans</artifactId>
 *     <scope>provided</scope>
 * </dependency>
 * }
 * </pre>
 *
 * By default it used Apache Rest Client for communicating with the OAuth2
 * Server.<br>
 *
 * Spring Security framework initializes the
 * {@link org.springframework.security.core.context.SecurityContext} with the
 * {@code OAuth2Authentication} which is provided as part of
 * {@link #loadAuthentication} method. <br>
 * This gives you the following options:
 * <ul>
 * <li>All Spring security features are supported that uses
 * {@link org.springframework.security.core.context.SecurityContext#getAuthentication()}</li>
 * <li>You can access the {@code Authentication} via
 * {@link SecurityContextHolder#getContext()} also within asynchronous
 * threads.</li>
 * <li>You can access the {@code Token} via
 * {@link SpringSecurityContext#getToken()} also within asynchronous
 * threads.</li>
 * </ul>
 *
 */
public class SAPOfflineTokenServicesCloud implements ResourceServerTokenServices, InitializingBean {

	private final OAuth2ServiceConfiguration serviceConfiguration;
	private Validator<Token> tokenValidator;
	private JwtValidatorBuilder jwtValidatorBuilder;
	private boolean useLocalScopeAsAuthorities;
	private ScopeConverter xsuaaScopeConverter;

	/**
	 * Constructs an instance which is preconfigured for XSUAA service configuration
	 * from SAP CP Environment.
	 */
	public SAPOfflineTokenServicesCloud() {
		this(Environments.getCurrent().getXsuaaConfiguration());
	}

	/**
	 * Constructs an instance with custom configuration.
	 *
	 * @param serviceConfiguration
	 *            the service configuration. You can use
	 *            {@link com.sap.cloud.security.config.Environments} in order to
	 *            load service configuration from the binding information in your
	 *            environment.
	 */
	public SAPOfflineTokenServicesCloud(OAuth2ServiceConfiguration serviceConfiguration) {
		this(serviceConfiguration, new RestTemplate());
	}

	/**
	 * Constructs an instance with custom configuration and rest template.
	 *
	 * @param serviceConfiguration
	 *            the service configuration. You can use
	 *            {@link com.sap.cloud.security.config.Environments} in order to
	 *            load service configuration from the binding information in your
	 *            environment.
	 * @param restOperations
	 *            the spring rest template
	 */
	public SAPOfflineTokenServicesCloud(OAuth2ServiceConfiguration serviceConfiguration,
			RestOperations restOperations) {
		this(serviceConfiguration, JwtValidatorBuilder.getInstance(serviceConfiguration)
				.withOAuth2TokenKeyService(new SpringOAuth2TokenKeyService(restOperations))
				.withOidcConfigurationService(new SpringOidcConfigurationService(restOperations)));
	}

	SAPOfflineTokenServicesCloud(OAuth2ServiceConfiguration serviceConfiguration,
			JwtValidatorBuilder jwtValidatorBuilder) {
		Assertions.assertNotNull(serviceConfiguration, "serviceConfiguration is required.");
		Assertions.assertNotNull(jwtValidatorBuilder, "jwtValidatorBuilder is required.");

		this.serviceConfiguration = serviceConfiguration;
		this.jwtValidatorBuilder = jwtValidatorBuilder;
		if (serviceConfiguration.hasProperty(CFConstants.XSUAA.APP_ID)) {
			this.xsuaaScopeConverter = new XsuaaScopeConverter(
					serviceConfiguration.getProperty(CFConstants.XSUAA.APP_ID));
		}
	}

	/**
	 * Configure another XSUAA instance, e.g. of plan broker.
	 *
	 * @param otherServiceConfiguration
	 *            another service configuration. You can use
	 *            {@link com.sap.cloud.security.config.cf.CFEnvironment#getXsuaaConfigurationForTokenExchange()}
	 *            in order to load additional broker service configuration from the
	 *            binding information in your environment.
	 * @return the instance itself
	 */
	public SAPOfflineTokenServicesCloud withAnotherServiceConfiguration(
			OAuth2ServiceConfiguration otherServiceConfiguration) {
		jwtValidatorBuilder.configureAnotherServiceInstance(otherServiceConfiguration);
		return this;
	}

	@Override
	public OAuth2Authentication loadAuthentication(@Nonnull String accessToken)
			throws AuthenticationException, InvalidTokenException {
		Token token = checkAndCreateToken(accessToken);

		ValidationResult validationResult = tokenValidator.validate(token);

		if (validationResult.isErroneous()) {
			throw new InvalidTokenException(validationResult.getErrorDescription());
		}
		SecurityContext.setToken(token);
		//return createOAuth2Authentication(serviceConfiguration.getClientId(), getScopes(token), token);
		// NGPBUG-125268
		return createOAuth2Authentication(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID), getScopes(token), token);
	}

	static OAuth2Authentication createOAuth2Authentication(String clientId, Set<String> scopes, Token token) {
		Authentication userAuthentication = getUserAuthentication(token, scopes);
		final AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, scopes);
		authorizationRequest.setAuthorities(createAuthorities(scopes));
		authorizationRequest.setApproved(true);
		return new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
	}

	@Nullable
	private static UserAuthenticationToken getUserAuthentication(Token token, Set<String> scopes) {
		GrantType grantType = null;
		if (token instanceof AccessToken) {
			grantType = ((AccessToken) token).getGrantType();
		}
		if (grantType == GrantType.CLIENT_CREDENTIALS || grantType == GrantType.CLIENT_X509) {
			return null;
		}
		return new UserAuthenticationToken(token, scopes);
	}

	private Set<String> getScopes(Token token) {
		Set<String> scopes = token instanceof AccessToken
				? ((AccessToken) token).getScopes()
				: Collections.emptySet();
		if (useLocalScopeAsAuthorities) {
			scopes = xsuaaScopeConverter.convert(scopes);
		}
		return scopes;
	}

	@Override
	public void afterPropertiesSet() {
		tokenValidator = jwtValidatorBuilder.build();
	}

	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: readAccessToken()");
	}

	/**
	 * This method allows to overwrite the default behavior of the authorities
	 * converter implementation.
	 *
	 * @param extractLocalScopesOnly
	 *            true when only local scopes are extracted. Local scopes means that
	 *            non-application specific scopes are filtered out and scopes are
	 *            returned without appId prefix, e.g. "Display".
	 * @return the token authenticator itself
	 */
	public SAPOfflineTokenServicesCloud setLocalScopeAsAuthorities(boolean extractLocalScopesOnly) {
		this.useLocalScopeAsAuthorities = extractLocalScopesOnly;
		return this;
	}

	private static Set<GrantedAuthority> createAuthorities(Collection<String> scopes) {
		return scopes.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
	}

	private Token checkAndCreateToken(@Nonnull String accessToken) {
		try {
			switch (serviceConfiguration.getService()) {
			case XSUAA:
				return new XsuaaToken(accessToken).withScopeConverter(xsuaaScopeConverter);
			case IAS:
				return new SapIdToken(accessToken);
			default:
				// TODO support IAS
				throw new InvalidTokenException(
						"AccessToken of service " + serviceConfiguration.getService() + " is not supported.");
			}
		} catch (Exception e) {
			throw new InvalidTokenException(e.getMessage());
		}
	}

	private static class UserAuthenticationToken extends AbstractAuthenticationToken {
		private final String username;

		public UserAuthenticationToken(Token token, Set<String> scopes) {
			super(SAPOfflineTokenServicesCloud.createAuthorities(scopes));
			this.username = token.getClaimAsString(TokenClaims.USER_NAME);
			setAuthenticated(true);
			setDetails(token);
		}

		@Override
		public String getName() {
			return username;
		}

		@Override
		public Object getCredentials() {
			return "N/A";
		}

		@Override
		public Object getPrincipal() {
			return username;
		}
	}
}
