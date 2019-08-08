package com.sap.cloud.security.xsuaa.token.flows;

import java.net.URI;

import com.sap.cloud.security.xsuaa.backend.ClientCredentials;
import com.sap.cloud.security.xsuaa.backend.OAuth2AccessToken;
import com.sap.cloud.security.xsuaa.backend.OAuth2Server;
import com.sap.cloud.security.xsuaa.backend.OAuth2ServerEndpointsProvider;
import com.sap.cloud.security.xsuaa.backend.OAuth2ServerException;
import com.sap.xsa.security.container.XSTokenRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * A refresh token flow builder. <br>
 * Applications can use this flow exchange a given refresh token for a
 * (refreshed) JWT token.
 */
public class RefreshTokenFlow {

	private XSTokenRequest request;
	private String refreshToken;
	private OAuth2Server oAuth2Server;
	private VariableKeySetUriTokenDecoder tokenDecoder;
    private OAuth2ServerEndpointsProvider endpointsProvider;

    /**
	 * Creates a new instance.
	 *
	 * @param oAuth2Server
	 *            - the {@link OAuth2Server} used to execute the final request.
	 * @param tokenDecoder
	 * 			  - the token decoder
	 * @param endpointsProvider
	 *            - the endpoints provider
	 */
	RefreshTokenFlow(OAuth2Server oAuth2Server, VariableKeySetUriTokenDecoder tokenDecoder, OAuth2ServerEndpointsProvider endpointsProvider) {
        Assert.notNull(oAuth2Server, "OAuth2Server must not be null.");
        Assert.notNull(tokenDecoder, "TokenDecoder must not be null.");
        Assert.notNull(endpointsProvider, "OAuth2ServerEndpointsProvider must not be null.");

        this.oAuth2Server = oAuth2Server;
        this.tokenDecoder = tokenDecoder;
        this.request = new XsuaaTokenFlowRequest(endpointsProvider.getTokenEndpoint());
        this.endpointsProvider = endpointsProvider;
    }

	/**
	 * Sets the mandatory refresh token to be exchanged for a (refreshed) JWT.
	 * 
	 * @param refreshToken
	 *            - the refresh token to be exchanged for a JWT.
	 * @return this builder object.
	 */
	public RefreshTokenFlow refreshToken(String refreshToken) {
		Assert.notNull(refreshToken, "RefreshToken must not be null.");
		this.refreshToken = refreshToken;
		return this;
	}

	/**
	 * The OAuth 2.0 client ID used to authenticate to XSUAA.
	 * 
	 * @param clientId
	 *            - the OAuth 2.0 client ID.
	 * @return this builder object.
	 */
	public RefreshTokenFlow client(String clientId) {
		request.setClientId(clientId);
		return this;
	}

	/**
	 * The OAuth 2.0 client secret used to authenticate to XSUAA.
	 * 
	 * @param clientSecret
	 *            - the OAuth 2.0 client secret.
	 * @return this builder object.
	 */
	public RefreshTokenFlow secret(String clientSecret) {
		request.setClientSecret(clientSecret);
		return this;
	}

	/**
	 * Executes the refresh token flow against XSUAA.
	 * 
	 * @return the refreshed JWT token or an exception in case the token could not
	 *         be refreshed.
	 * @throws TokenFlowException
	 *             in case of an error during the flow, or when the token cannot be
	 *             refreshed.
	 */
	public Jwt execute() throws TokenFlowException {
		checkRequest(request);

		return refreshToken(refreshToken, request);
	}

	/**
	 * Checks that all mandatory fields of the token flow request have been set.
	 * Otherwise throws an exception.
	 * 
	 * @param request
	 *            - the request to check.
	 * @throws TokenFlowException
	 *             in case not all mandatory fields of the token flow request have
	 *             been set.
	 */
	private void checkRequest(XSTokenRequest request) throws TokenFlowException {
		if (refreshToken == null) {
			throw new TokenFlowException(
					"Refresh token not set. Make sure to have called the refreshToken() method on RefreshTokenFlow builder.");
		}

		if (!request.isValid()) {
			throw new TokenFlowException(
					"Refresh token flow request is not valid. Make sure all mandatory fields are set.");
		}
	}

	/**
	 * Refreshes the token based on the given {@code refreshToken} instance.
	 * 
	 * @param refreshToken
	 *            - the (opaque) refresh token.
	 * @param request
	 *            - the token flow request to execute.
	 * @return the JWT received in exchange for the refresh token.
	 * @throws TokenFlowException
	 *             in case of an error in the flow.
	 */
	private Jwt refreshToken(String refreshToken, XSTokenRequest request) throws TokenFlowException {
		try {
			OAuth2AccessToken accessToken = oAuth2Server.retrieveAccessTokenViaRefreshToken(request.getTokenEndpoint(), new ClientCredentials(request.getClientId(), request.getClientSecret()), refreshToken);
			return decode(accessToken.getValue(), endpointsProvider.getJwksUri());
		} catch (OAuth2ServerException e) {
			throw new TokenFlowException(String.format("Error refreshing token with grant_type 'refresh_token': %s", e.getMessage()));
		}
	}

	/**
	 * Decodes the returned JWT value.
	 * validation is not required by the one who retrieves the token,
	 * but by the one who receives it (e.g. the service it is sent to).
	 * Hence, here we only decode, but do not validate.
	 * decoder.setJwtValidator(new
	 * DelegatingOAuth2TokenValidator<>(tokenValidators));
	 *
	 * @param encodedToken - the encoded JWT token value.
	 * @return the decoded JWT.
	 * @throws TokenFlowException in case of an exception decoding the token.
	 */
	private Jwt decode(String encodedToken, URI keySetEndpoint) {
		// TODO not a good idea as singleton bean instance
		tokenDecoder.setJwksURI(keySetEndpoint);
		return tokenDecoder.decode(encodedToken);
	}
}
