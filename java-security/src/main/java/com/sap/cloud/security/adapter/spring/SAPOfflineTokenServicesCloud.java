package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;
import com.sap.cloud.security.xsuaa.client.SpringOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.SpringOidcConfigurationService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This constructor requires a dependency to Spring oauth and web.
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
 */
public class SAPOfflineTokenServicesCloud implements ResourceServerTokenServices, InitializingBean {

	private final OAuth2ServiceConfiguration serviceConfiguration;
	private Validator<Token> tokenValidator;
	private JwtValidatorBuilder jwtValidatorBuilder;
	private boolean useLocalScopeAsAuthorities;
	private ScopeConverter xsuaaScopeConverter;


	/**
	 * Constructs an instance which can be used in the SAP CP Environment.
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
				.withOAuth2TokenKeyService(
						OAuth2TokenKeyServiceWithCache.getInstance()
								.withTokenKeyService(new SpringOAuth2TokenKeyService(restOperations)))
				.withOidcConfigurationService(
						OidcConfigurationServiceWithCache.getInstance()
								.withOidcConfigurationService(new SpringOidcConfigurationService(restOperations))));

	}

	SAPOfflineTokenServicesCloud(OAuth2ServiceConfiguration serviceConfiguration,
			JwtValidatorBuilder jwtValidatorBuilder) {
		Assertions.assertNotNull(serviceConfiguration, "serviceConfiguration is required.");
		Assertions.assertNotNull(jwtValidatorBuilder, "jwtValidatorBuilder is required.");

		this.serviceConfiguration = serviceConfiguration;
		this.jwtValidatorBuilder = jwtValidatorBuilder;
		if(serviceConfiguration.hasProperty(CFConstants.XSUAA.APP_ID)) {
			this.xsuaaScopeConverter = new XsuaaScopeConverter(serviceConfiguration.getProperty(CFConstants.XSUAA.APP_ID));
		}
	}

	@Override
	public OAuth2Authentication loadAuthentication(@Nonnull String accessToken)
			throws AuthenticationException, InvalidTokenException {
		XsuaaToken token = checkAndCreateToken(accessToken);

		List<String> scopes = token.getScopes();
		if(useLocalScopeAsAuthorities) {
			scopes = xsuaaScopeConverter.convert(scopes);
		}
		ValidationResult validationResult = tokenValidator.validate(token);

		if (validationResult.isValid()) {
			AuthorizationRequest authorizationRequest = new AuthorizationRequest(new HashMap<>(), null,
					serviceConfiguration.getClientId(), scopes.stream().collect(Collectors.toSet()), new HashSet<>(), null,
					true, "", "", null);
			SecurityContext.setToken(token);
			return new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);
		} else {
			throw new InvalidTokenException(validationResult.getErrorDescription());
		}
	}

	@Override
	public void afterPropertiesSet() {
		tokenValidator = jwtValidatorBuilder.build();
	}

	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}

	/**
	 * This method allows to overwrite the default behavior of the
	 * authorities converter implementation.
	 *
	 * @param extractLocalScopesOnly
	 *            true when only local scopes are extracted.
	 *            Local scopes means that non-application specific scopes
	 *            are filtered out and scopes are returned without appId prefix,
	 *            e.g. "Display".
	 * @return the token authenticator itself
	 */
	public SAPOfflineTokenServicesCloud setLocalScopeAsAuthorities(boolean extractLocalScopesOnly) {
		this.useLocalScopeAsAuthorities = extractLocalScopesOnly;
		return this;
	}

	private XsuaaToken checkAndCreateToken(@Nonnull String accessToken) {
		try {
			return new XsuaaToken(accessToken).withScopeConverter(xsuaaScopeConverter);
		} catch (Exception e) {
			throw new InvalidTokenException(e.getMessage());
		}
	}
}