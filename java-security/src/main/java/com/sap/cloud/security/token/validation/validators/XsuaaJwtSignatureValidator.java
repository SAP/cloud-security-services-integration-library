package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Map;

import static com.sap.cloud.security.config.ServiceConstants.XSUAA.UAA_DOMAIN;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.*;

/**
 * Jwt Signature validator for Access tokens issued by Xsuaa service
 */
class XsuaaJwtSignatureValidator extends JwtSignatureValidator {
    XsuaaJwtSignatureValidator(OAuth2ServiceConfiguration configuration, OAuth2TokenKeyServiceWithCache tokenKeyService, OidcConfigurationServiceWithCache oidcConfigurationService) {
        super(configuration, tokenKeyService, oidcConfigurationService);
    }

    @Override
    protected PublicKey getPublicKey(Token token, JwtSignatureAlgorithm algorithm) throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey key = null;

        try {
            key = fetchPublicKey(token, algorithm);
        } catch (OAuth2ServiceException | InvalidKeySpecException | NoSuchAlgorithmException | IllegalArgumentException e) {
            if (!configuration.hasProperty(ServiceConstants.XSUAA.VERIFICATION_KEY)) {
                throw e;
            }
        }

        if (key == null && configuration.hasProperty(ServiceConstants.XSUAA.VERIFICATION_KEY)) {
            String fallbackKey = configuration.getProperty(ServiceConstants.XSUAA.VERIFICATION_KEY);
            try {
                key = JsonWebKeyImpl.createPublicKeyFromPemEncodedPublicKey(JwtSignatureAlgorithm.RS256, fallbackKey);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new IllegalArgumentException("Fallback validation key supplied via " + ServiceConstants.XSUAA.VERIFICATION_KEY + " property in service credentials could not be used: {}", ex);
            }
        }

        return key;
    }


    private PublicKey fetchPublicKey(Token token, JwtSignatureAlgorithm algorithm) throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
        String keyId = configuration.isLegacyMode() ? KEY_ID_VALUE_LEGACY : token.getHeaderParameterAsString(KID_PARAMETER_NAME);
        if (keyId == null) {
            throw new IllegalArgumentException("Token does not contain the mandatory " + KID_PARAMETER_NAME + " header.");
        }

        String jwksUri = configuration.isLegacyMode() ? configuration.getUrl() + "/token_keys" : configuration.getProperty(UAA_DOMAIN) + "/token_keys";
        if (jwksUri == null) {
            throw new IllegalArgumentException("Token does not contain the mandatory " + JKU_PARAMETER_NAME + " header.");
        }
        URI uri = URI.create(jwksUri);
        uri =  uri.isAbsolute() ? uri : URI.create("https://" + jwksUri);
        Map<String, String> params = Collections.singletonMap(HttpHeaders.X_ZID, token.getAppTid());
        return tokenKeyService.getPublicKey(algorithm, keyId, uri, params);
    }
}
