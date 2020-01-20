package com.sap.cloud.security.spring.adapter;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class SAPOfflineTokenServicesCloud implements ResourceServerTokenServices, InitializingBean {

	private final OAuth2ServiceConfiguration serviceConfiguration;
	private Validator<Token> tokenValidator;

	public SAPOfflineTokenServicesCloud(OAuth2ServiceConfiguration serviceConfiguration) {
		this(serviceConfiguration, JwtValidatorBuilder.getInstance(serviceConfiguration).build());
	}

	SAPOfflineTokenServicesCloud(OAuth2ServiceConfiguration serviceConfiguration, Validator<Token> tokenValidator) {
		this.serviceConfiguration = serviceConfiguration;
		this.tokenValidator = tokenValidator;
	}

	@Override
	public OAuth2Authentication loadAuthentication(@Nonnull String accessToken)
			throws AuthenticationException, InvalidTokenException {

		Token token = checkAndCreateToken(accessToken);
		Set<String> scopes = token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES).stream().collect(Collectors.toSet());
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

	@Override
	public void afterPropertiesSet() {
	}

	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}

	private Token checkAndCreateToken(@Nonnull String accessToken) {
		Service service = serviceConfiguration.getService();
		if (service == null) {
			throw new IllegalStateException(
					String.format("Service configuration contains no service. VCAP_SERVICES missing?"));
		}
		try {
			switch (service) {
			case XSUAA:
				return new XsuaaToken(accessToken);
			case IAS:
				return new IasToken(accessToken);
			}
		} catch (Exception e) {
			// catches exceptions during token creation and re-throws with spring specific exception
			throw new InvalidTokenException(e.getMessage());
		}
		throw new IllegalStateException(String.format("Service configuration '%s' not supported yet", service));
	}
}