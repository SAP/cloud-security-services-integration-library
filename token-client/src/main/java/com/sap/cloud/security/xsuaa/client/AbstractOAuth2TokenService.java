package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.util.UriUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

public abstract class AbstractOAuth2TokenService implements OAuth2TokenService {

	private static Logger logger = LoggerFactory.getLogger(XsuaaOAuth2TokenService.class);
	private final HttpHeadersFactory httpHeadersFactory;

	public AbstractOAuth2TokenService() {
		this.httpHeadersFactory = new HttpHeadersFactory();
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		Assertions.assertNotNull(clientCredentials, "clientCredentials is required");

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
		Assertions.assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		Assertions.assertNotNull(clientCredentials, "clientCredentials is required");
		Assertions.assertNotNull(token, "token is required");

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
		Assertions.assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		Assertions.assertNotNull(clientCredentials, "clientCredentials is required");
		Assertions.assertNotNull(refreshToken, "refreshToken is required");

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
		Assertions.assertNotNull(tokenEndpoint, "tokenEndpoint is required");
		Assertions.assertNotNull(clientCredentials, "clientCredentials are required");
		Assertions.assertNotNull(username, "username is required");
		Assertions.assertNotNull(password, "password is required");

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
		Assertions.assertNotNull(tokenEndpoint, "tokenEndpoint is required");
		Assertions.assertNotNull(clientCredentials, "clientCredentials are required");
		Assertions.assertNotNull(token, "token is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_JWT_BEARER)
				.withClientCredentials(clientCredentials)
				.withToken(token)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpoint, subdomain), headers, parameters);
	}

	/**
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
