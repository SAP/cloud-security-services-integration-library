package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.*;

/**
 * Jwt Signature validator for Access tokens issued by Xsuaa service
 */
class XsuaaJwtSignatureValidator extends JwtSignatureValidator {
    public static final String FALLBACK_KEY = "verificationkey";

    XsuaaJwtSignatureValidator(OAuth2ServiceConfiguration configuration, OAuth2TokenKeyServiceWithCache tokenKeyService, OidcConfigurationServiceWithCache oidcConfigurationService) {
        super(configuration, tokenKeyService, oidcConfigurationService);
    }

    @Override
    protected PublicKey getPublicKey(Token token, JwtSignatureAlgorithm algorithm) throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey key = null;

        try {
            key = fetchPublicKey(token, algorithm);
        } catch (OAuth2ServiceException | InvalidKeySpecException | NoSuchAlgorithmException | IllegalArgumentException e) {
            if (!configuration.hasProperty(FALLBACK_KEY)) {
                throw e;
            }
        }

        if(key == null && configuration.hasProperty(FALLBACK_KEY)) {
            String fallbackKey = configuration.getProperty(FALLBACK_KEY);

            try {
                key = JsonWebKeyImpl.createPublicKeyFromPemEncodedPublicKey(JwtSignatureAlgorithm.RS256, fallbackKey);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new IllegalArgumentException("Fallback validation key supplied via " + FALLBACK_KEY + " property in service credentials could not be used: {}", ex);
            }
        }

        return key;
    }


    private PublicKey fetchPublicKey(Token token, JwtSignatureAlgorithm algorithm) throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
        String keyId = configuration.isLegacyMode() ? KEY_ID_VALUE_LEGACY : token.getHeaderParameterAsString(KID_PARAMETER_NAME);
        if (keyId == null) {
            throw new IllegalArgumentException("Token does not contain the mandatory " + KID_PARAMETER_NAME + " header.");
        }

        String jwksUri = configuration.isLegacyMode() ? configuration.getUrl() + "/token_keys" : token.getHeaderParameterAsString(JKU_PARAMETER_NAME);
        if (jwksUri == null) {
            throw new IllegalArgumentException("Token does not contain the mandatory " + JKU_PARAMETER_NAME + " header.");
        }

        return tokenKeyService.getPublicKey(algorithm, keyId, URI.create(jwksUri), null, configuration.getClientId(), null);
    }
}
