package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.util.UriUtil;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

public abstract class AbstractOAuth2TokenService implements OAuth2TokenService {

	protected final HttpHeadersFactory httpHeadersFactory;

	public AbstractOAuth2TokenService() {
		this.httpHeadersFactory = new HttpHeadersFactory();
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials, "clientCredentials is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_CLIENT_CREDENTIALS)
				.withClientCredentials(clientCredentials)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpointUri, subdomain), headers, parameters);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaUserTokenGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials, @Nonnull String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials, "clientCredentials is required");
		assertNotNull(token, "token is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_USER_TOKEN)
				.withClientId(clientCredentials.getId())
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = httpHeadersFactory.createWithAuthorizationBearerHeader(token);

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpointUri, subdomain), headers, parameters);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials,
			@Nonnull String refreshToken, String subdomain) throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials, "clientCredentials is required");
		assertNotNull(refreshToken, "refreshToken is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_REFRESH_TOKEN)
				.withRefreshToken(refreshToken)
				.withClientCredentials(clientCredentials)
				.buildAsMap();

		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpointUri, subdomain), headers, parameters);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(@Nonnull URI tokenEndpoint,
			@Nonnull ClientCredentials clientCredentials, @Nonnull String username, @Nonnull String password,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpoint, "tokenEndpoint is required");
		assertNotNull(clientCredentials, "clientCredentials are required");
		assertNotNull(username, "username is required");
		assertNotNull(password, "password is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_PASSWORD)
				.withUsername(username)
				.withPassword(password)
				.withClientCredentials(clientCredentials)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpoint, subdomain), headers, parameters);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpoint,
			ClientCredentials clientCredentials, String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters) throws OAuth2ServiceException {
		assertNotNull(tokenEndpoint, "tokenEndpoint is required");
		assertNotNull(clientCredentials, "clientCredentials are required");
		assertNotNull(token, "token is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_JWT_BEARER)
				.withClientCredentials(clientCredentials)
				.withToken(token)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpoint, subdomain), headers, parameters);
	}

	public OAuth2TokenResponse retrieveAccessTokenViaX509(URI delegationEndpointUri,
			String clientId, String consumerCertificate,
			@Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters) throws OAuth2ServiceException {

		assertNotNull(delegationEndpointUri, "delegationEndpointUri is required");
		assertNotNull(clientId, "clientId is required"); // master
		assertHasText(consumerCertificate, "consumerCertificate is required"); // w/o BEGIN CERTIFICATE ...

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_CLIENT_X509) // default
				.withParameter(MASTER_CLIENT_ID, clientId)
				.withParameter(CLONE_CERTIFICATE, consumerCertificate)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(delegationEndpointUri, subdomain), headers, parameters);
	}

	public OAuth2TokenResponse retrieveAccessTokenViaX509AndJwtBearerGrant(URI delegationEndpointUri,
			String clientId, String consumerCertificate, String oidcToken,
			@Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters) throws OAuth2ServiceException {

		assertNotNull(delegationEndpointUri, "delegationEndpointUri is required");
		assertNotNull(clientId, "clientId is required (master)");
		assertHasText(consumerCertificate, "consumerToken is required (clone)"); // w/o BEGIN CERTIFICATE ...
		assertHasText(oidcToken, "oidcToken is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_JWT_BEARER)
				.withParameter(ASSERTION, oidcToken)
				.withParameter(MASTER_CLIENT_ID, clientId)
				.withParameter(CLONE_CERTIFICATE, consumerCertificate)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(delegationEndpointUri, subdomain), headers, parameters);
	}

	/**
	 * Implements the HTTP client specific logic to perform an HTTP request and
	 * handle the response.
	 *
	 * @param tokenEndpointUri
	 *            the URI of the token endpoint the request must be sent to.
	 * @param headers
	 *            the HTTP headers that must be sent with the request.
	 * @param parameters
	 *            a map of request parameters that must be sent with the request.
	 * @return the token response.
	 * @throws OAuth2ServiceException
	 *             when the request ot the token endpoint fails or returns an error
	 *             code.
	 */
	protected abstract OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> parameters) throws OAuth2ServiceException;

}
