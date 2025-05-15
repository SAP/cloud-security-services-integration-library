package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.x509.X509Certificate;
import com.sap.cloud.security.x509.X509Constants;
import com.sap.cloud.security.xsuaa.client.DefaultOidcConfigurationService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;

import javax.annotation.Nonnull;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.token.validation.validators.JsonWebKey.DEFAULT_KEY_ID;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.KID_PARAMETER_NAME;

/**
 * Jwt Signature validator for OIDC tokens issued by Identity service. This validator MUST only be
 * called after validating the token's issuer claim via {@link JwtIssuerValidator} first.
 */
class SapIdJwtSignatureValidator extends JwtSignatureValidator {
	private boolean isTenantIdCheckEnabled = true;
	private boolean isProofTokenValidationEnabled = false;

	SapIdJwtSignatureValidator(OAuth2ServiceConfiguration configuration, OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		super(configuration, tokenKeyService, oidcConfigurationService);
	}

	/**
	 * Disables the tenant id check. In case JWT issuer (`iss` claim) differs from `url` attribute of
	 * {@link OAuth2ServiceConfiguration}, claim {@link TokenClaims#SAP_GLOBAL_APP_TID} needs to be present in token to
	 * ensure that the tenant belongs to this issuer.
	 * <p>
	 * Use with caution as it relaxes the validation rules! It is not recommended to disable this check for standard
	 * Identity service setup.
	 */
	protected void disableTenantIdCheck() {
		this.isTenantIdCheckEnabled = false;
	}

	/**
	 * Enables ProofToken Validation check for forwarded client certificates. If the check is enabled and no forwarded
	 * certificate in the request is available, the token will be evaluated as invalid.
	 * With this check enabled, the forwarded certificate is added to the token keys request.
	 */
	protected void enableProofTokenValidationCheck() {
		this.isProofTokenValidationEnabled = true;
	}

	@Override
	protected PublicKey getPublicKey(Token token, JwtSignatureAlgorithm algorithm) throws OAuth2ServiceException {
		String keyId = DEFAULT_KEY_ID;
		if (token.hasHeaderParameter(KID_PARAMETER_NAME)) {
			keyId = token.getHeaderParameterAsString(KID_PARAMETER_NAME);
		}
		OAuth2TokenKeyServiceWithCache.KeyParameters keyParams = new OAuth2TokenKeyServiceWithCache.KeyParameters(
				algorithm, keyId, getJwksUri(token));

		Map<String, String> requestParams = new HashMap<>(3, 1);
		OAuth2TokenKeyServiceWithCache.CacheKey cacheKey;

		requestParams.put(HttpHeaders.X_APP_TID, token.getAppTid());
		requestParams.put(HttpHeaders.X_CLIENT_ID, configuration.getClientId());
		requestParams.put(HttpHeaders.X_AZP, token.getClaimAsString(TokenClaims.AUTHORIZATION_PARTY));
		if (isProofTokenValidationEnabled && !token.hasClaim(TokenClaims.IAS_APIS)) {
			X509Certificate cert = (X509Certificate) SecurityContext.getClientCertificate();

			if (cert == null) {
				throw new OAuth2ServiceException("Client certificate for proof token validation could not be read from 'x-forwarded-client-cert' header.");
			} else {
				Map<String, String> cacheKeyParams = new HashMap<>(requestParams);

				requestParams.put(HttpHeaders.X_CLIENT_CERT, cert.getPEM());
				cacheKeyParams.put(X509Constants.FWD_CLIENT_CERT_SUB, cert.getSubjectDN());

				cacheKey = new OAuth2TokenKeyServiceWithCache.CacheKey(keyParams.keyUri(), cacheKeyParams);
			}
		} else {
			cacheKey = new OAuth2TokenKeyServiceWithCache.CacheKey(keyParams.keyUri(), requestParams);
		}

		try {
			return tokenKeyService.getPublicKey(keyParams, requestParams, cacheKey);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}
	}

	private URI getJwksUri(Token token) throws OAuth2ServiceException {
		String domain = token.getIssuer();
		if (domain == null) {
			throw new IllegalArgumentException("Token does not contain mandatory " + TokenClaims.ISSUER + " header.");
		}

		if (isTenantIdCheckEnabled && !domain.equals("" + configuration.getUrl()) && token.getAppTid() == null) {
			throw new IllegalArgumentException("OIDC token must provide the " + TokenClaims.SAP_GLOBAL_APP_TID
					+ " claim for tenant validation when issuer is not the same as the url from the service credentials.");
		}

		return this.getOidcJwksUri(domain);
	}

	/**
	 * Fetches the JWKS URI from the OIDC .well-known endpoint under the given domain that must have already been
	 * validated to be trustworthy in advance, e.g. with an additional {@link JwtIssuerValidator}.
	 *
	 * @param domain
	 * 		a trustworthy domain that supplies an OIDC .well-known endpoint
	 * @return the URI to the JWKS of the OIDC service under the given domain
	 * @throws OAuth2ServiceException
	 * 		if server call fails
	 */
	@Nonnull
	private URI getOidcJwksUri(String domain) throws OAuth2ServiceException {
		URI discoveryUri = DefaultOidcConfigurationService.getDiscoveryEndpointUri(domain);
		if (discoveryUri == null) {
			throw new IllegalArgumentException("OIDC .well-known discovery URI could not be constructed.");
		}

		OAuth2ServiceEndpointsProvider endpointsProvider = oidcConfigurationService
				.getOrRetrieveEndpoints(discoveryUri);
		if (endpointsProvider == null) {
			throw new OAuth2ServiceException("OIDC .well-known configuration could not be retrieved.");
		}

		URI jkuUri = endpointsProvider.getJwksUri();
		if (jkuUri == null) {
			throw new IllegalArgumentException("OIDC .well-known response did not contain JWKS URI.");
		}

		return jkuUri;
	}
}
