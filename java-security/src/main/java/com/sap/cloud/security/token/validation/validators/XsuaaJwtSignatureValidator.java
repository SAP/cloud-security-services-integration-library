package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.XsuaaJkuFactory;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static com.sap.cloud.security.config.ServiceConstants.XSUAA.UAA_DOMAIN;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.KEY_ID_VALUE_LEGACY;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.KID_PARAMETER_NAME;

/**
 * Jwt Signature validator for Access tokens issued by Xsuaa service
 */
class XsuaaJwtSignatureValidator extends JwtSignatureValidator {
	public static final Logger LOGGER = LoggerFactory.getLogger(XsuaaJwtSignatureValidator.class);

	/*
	 * The following list of factories brings backward-compatibility for test
	 * credentials in consumer applications written before 2.17.0 that are used to
	 * validate java-security-test tokens. This is necessary to construct the
	 * correct JKU when 'localhost' without port is defined as uaadomain in the
	 * service credentials. Implementations of this interface absolutely MUST NOT be
	 * supplied outside test scope and MUST NOT be used for any other purpose to
	 * preserve application security.
	 */
	List<XsuaaJkuFactory> jkuFactories = new ArrayList<>() {
		{
			try {
				ServiceLoader.load(XsuaaJkuFactory.class).forEach(this::add);
				LOGGER.debug("loaded XsuaaJkuFactory service providers: {}", this);
			} catch (Exception | ServiceConfigurationError e) {
				LOGGER.warn("Unexpected failure while loading XsuaaJkuFactory service providers: {}", e.getMessage());
			}
		}
	};

	XsuaaJwtSignatureValidator(OAuth2ServiceConfiguration configuration, OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		super(configuration, tokenKeyService, oidcConfigurationService);
	}

	@Override
	protected PublicKey getPublicKey(Token token, JwtSignatureAlgorithm algorithm)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key = null;

		try {
			key = fetchPublicKey(token, algorithm);
		} catch (OAuth2ServiceException | InvalidKeySpecException | NoSuchAlgorithmException
				| IllegalArgumentException e) {
			if (!configuration.isLegacyMode()) {
				LOGGER.error("Error fetching public key from XSUAA service: {}", e.getMessage());
			}
			if (!configuration.hasProperty(ServiceConstants.XSUAA.VERIFICATION_KEY)) {
				throw e;
			}

			String fallbackKey = configuration.getProperty(ServiceConstants.XSUAA.VERIFICATION_KEY);
			try {
				key = JsonWebKeyImpl.createPublicKeyFromPemEncodedPublicKey(JwtSignatureAlgorithm.RS256,
						fallbackKey);
			} catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
				IllegalArgumentException illegalArgEx = new IllegalArgumentException(
						"Fallback validation key supplied via " + ServiceConstants.XSUAA.VERIFICATION_KEY
								+ " property in service credentials could not be used: " + ex.getMessage());
				if (e instanceof OAuth2ServiceException) {
					e.addSuppressed(illegalArgEx);
					throw e;
				}
				throw illegalArgEx;
			}
		}

		return key;
	}

	private PublicKey fetchPublicKey(Token token, JwtSignatureAlgorithm algorithm)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		String keyId = configuration.isLegacyMode() ? KEY_ID_VALUE_LEGACY
				: token.getHeaderParameterAsString(KID_PARAMETER_NAME);
		if (keyId == null) {
			throw new IllegalArgumentException(
					"Token does not contain the mandatory " + KID_PARAMETER_NAME + " header.");
		}

		String zidQueryParam = composeZidQueryParameter(token);

		String jwksUri;
		if (jkuFactories.isEmpty()) {
			jwksUri = configuration.isLegacyMode()
					? configuration.getUrl() + "/token_keys"
					: configuration.getProperty(UAA_DOMAIN) + "/token_keys" + zidQueryParam;
		} else {
			LOGGER.info("Loaded custom JKU factory");
			jwksUri = jkuFactories.get(0).create(token.getTokenValue());
		}

		URI uri = URI.create(jwksUri);
		uri = uri.isAbsolute() ? uri : URI.create("https://" + jwksUri);
		Map<String, String> params = Collections.singletonMap(HttpHeaders.X_ZID, token.getAppTid());
		return tokenKeyService.getPublicKey(new OAuth2TokenKeyServiceWithCache.KeyParameters(algorithm, keyId, uri),
				params);
	}

	private String composeZidQueryParameter(Token token) {
		String zid = token.getAppTid();
		if (zid != null && !zid.isBlank()) {
			return "?zid=" + zid;
		}
		return "";
	}
}
