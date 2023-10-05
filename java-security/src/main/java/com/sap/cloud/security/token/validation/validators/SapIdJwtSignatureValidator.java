package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.xsuaa.client.DefaultOidcConfigurationService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;

import javax.annotation.Nonnull;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.sap.cloud.security.token.validation.validators.JsonWebKey.DEFAULT_KEY_ID;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.KID_PARAMETER_NAME;

/**
 * Jwt Signature validator for OIDC tokens issued by Identity service
 */
class SapIdJwtSignatureValidator extends JwtSignatureValidator {
    private boolean isTenantIdCheckEnabled = true;

    SapIdJwtSignatureValidator(OAuth2ServiceConfiguration configuration, OAuth2TokenKeyServiceWithCache tokenKeyService, OidcConfigurationServiceWithCache oidcConfigurationService) {
        super(configuration, tokenKeyService, oidcConfigurationService);
    }

    /**
     * Disables the tenant id check. In case JWT issuer (`iss` claim) differs from `url` attribute of
     * {@link OAuth2ServiceConfiguration}, claim {@link TokenClaims#SAP_GLOBAL_APP_TID} needs to be
     * present in token to ensure that the tenant belongs to this issuer.
     * <p>
     * Use with caution as it relaxes the validation rules! It is not recommended to
     * disable this check for standard Identity service setup.
     */
    protected void disableTenantIdCheck() {
        this.isTenantIdCheckEnabled = false;
    }

    @Override
    protected PublicKey getPublicKey(Token token, JwtSignatureAlgorithm algorithm) throws OAuth2ServiceException {
        String keyId = DEFAULT_KEY_ID;
        if (token.hasHeaderParameter(KID_PARAMETER_NAME)) {
            keyId = token.getHeaderParameterAsString(KID_PARAMETER_NAME);
        }

        URI jkuUri = getJwksUri(token);
        String appTid = token.getAppTid();
        String clientId = configuration.getClientId();
        String azp = token.getClaimAsString(TokenClaims.AUTHORIZATION_PARTY);

        try {
            return tokenKeyService.getPublicKey(algorithm, keyId, jkuUri, appTid, clientId, azp);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private URI getJwksUri(Token token) throws OAuth2ServiceException {
        String domain = token.getIssuer();
        if(domain == null) {
            throw new IllegalArgumentException("Token does not contain mandatory " + TokenClaims.ISSUER + " header.");
        }

        if (isTenantIdCheckEnabled && !domain.equals("" + configuration.getUrl()) && token.getAppTid() == null) {
            throw new IllegalArgumentException("OIDC token must provide a valid " + TokenClaims.SAP_GLOBAL_APP_TID + " header when issuer has a different domain than the url from the service credentials.");
        }


        return this.getOidcJwksUri(domain);
    }

    /**
     * Fetches the JWKS URI from the OIDC .well-known endpoint under the given domain that must have already been validated to be trustworthy in advance, e.g. with an additional {@link JwtIssuerValidator}.
     *
     * @param domain a trustworthy domain that supplies an OIDC .well-known endpoint
     * @return the URI to the JWKS of the OIDC service under the given domain
     * @throws OAuth2ServiceException if server call fails
     */
    @Nonnull
    private URI getOidcJwksUri(String domain) throws OAuth2ServiceException {
        URI discoveryUri = DefaultOidcConfigurationService.getDiscoveryEndpointUri(domain);

        OAuth2ServiceEndpointsProvider endpointsProvider = oidcConfigurationService.getOrRetrieveEndpoints(discoveryUri);
        if(endpointsProvider == null) {
            throw new OAuth2ServiceException("OIDC .well-known configuration could not be retrieved.");
        }

        URI jkuUri = endpointsProvider.getJwksUri();
        if (jkuUri == null) {
            throw new IllegalArgumentException("OIDC .well-known response did not contain JWKS URI.");
        }

        return jkuUri;
    }
}
