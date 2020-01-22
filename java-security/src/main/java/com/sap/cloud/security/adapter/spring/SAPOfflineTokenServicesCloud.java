package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
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
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;
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

	private final Supplier<Validator<Token>> validatorSupplier;
	private final OAuth2ServiceConfiguration serviceConfiguration;
	private Validator<Token> tokenValidator;

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
		this(serviceConfiguration, () -> JwtValidatorBuilder.getInstance(serviceConfiguration)
				.withOAuth2TokenKeyService(
						OAuth2TokenKeyServiceWithCache.getInstance()
								.withTokenKeyService(new SpringOAuth2TokenKeyService(restOperations)))
				.withOidcConfigurationService(
						OidcConfigurationServiceWithCache.getInstance()
								.withOidcConfigurationService(new SpringOidcConfigurationService(restOperations)))
				.build());
	}

	SAPOfflineTokenServicesCloud(OAuth2ServiceConfiguration serviceConfiguration,
			Supplier<Validator<Token>> validatorSupplier) {
		this.serviceConfiguration = serviceConfiguration;
		this.validatorSupplier = validatorSupplier;
	}

	@Override
	public OAuth2Authentication loadAuthentication(@Nonnull String accessToken)
			throws AuthenticationException, InvalidTokenException {
		XsuaaToken token = checkAndCreateToken(accessToken);
		Set<String> scopes = token.getScopes().stream().collect(Collectors.toSet());
		ValidationResult validationResult = tokenValidator.validate(token);

		if (validationResult.isValid()) {
			AuthorizationRequest authorizationRequest = new AuthorizationRequest(new HashMap<>(), null,
					serviceConfiguration.getClientId(), scopes, new HashSet<>(), null,
					true, "", "", null);
			return new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);
		} else {
			throw new InvalidTokenException(validationResult.getErrorDescription());
		}
	}

	private XsuaaToken checkAndCreateToken(@Nonnull String accessToken) {
		try {
			return new XsuaaToken(accessToken);
		} catch (Exception e) {
			throw new InvalidTokenException(e.getMessage());
		}
	}

	@Override
	public void afterPropertiesSet() {
		tokenValidator = validatorSupplier.get();
	}

	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}
}