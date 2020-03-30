package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.ScopeConverter;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaScopeConverter;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.SpringOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.SpringOidcConfigurationService;
import org.springframework.beans.factory.InitializingBean;
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
	 *            {@link com.sap.cloud.security.config.cf.CFEnvironment#getXsuaaConfigurationForTokenExchange()} in order to
	 *            load additional broker service configuration from the binding information in your
	 *            environment.
	 * @return the instance itself
	 */
	public SAPOfflineTokenServicesCloud withAnotherServiceConfiguration(OAuth2ServiceConfiguration otherServiceConfiguration) {
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

		return getOAuth2Authentication(serviceConfiguration.getClientId(), getScopes(token));
	}

	static OAuth2Authentication getOAuth2Authentication(String clientId, Set<String> scopes) {
		Authentication userAuthentication = null; // TODO no SAPUserDetails support. Using spring alternative?

		final AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, scopes);
		authorizationRequest.setAuthorities(getAuthorities(scopes));
		authorizationRequest.setApproved(true);

		return new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
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

	private static Set<GrantedAuthority> getAuthorities(Collection<String> scopes) {
		return scopes.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
	}

	private Token checkAndCreateToken(@Nonnull String accessToken) {
		try {
			switch (serviceConfiguration.getService()) {
			case XSUAA:
				return new XsuaaToken(accessToken).withScopeConverter(xsuaaScopeConverter);
			default:
				// TODO support IAS
				throw new InvalidTokenException(
						"AccessToken of service " + serviceConfiguration.getService() + " is not supported.");
			}
		} catch (Exception e) {
			throw new InvalidTokenException(e.getMessage());
		}
	}
}
