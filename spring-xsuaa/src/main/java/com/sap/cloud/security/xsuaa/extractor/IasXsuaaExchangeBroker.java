package com.sap.cloud.security.xsuaa.extractor;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;

/**
 * IAS token and XSUAA token exchange and resolution class. Can be used to
 * distinguish between IAS and XSUAA tokens. Controls token exchange between IAS
 * and XSUAA by using IAS_XSUAA_XCHANGE_ENABLED environment variable flag
 */
public class IasXsuaaExchangeBroker implements BearerTokenResolver {

	private static final Logger logger = LoggerFactory.getLogger(IasXsuaaExchangeBroker.class);

	private final XsuaaTokenFlows xsuaaTokenFlows;
	private static final String AUTH_HEADER = "Authorization";

	public IasXsuaaExchangeBroker(XsuaaTokenFlows xsuaaTokenFlows) {
		this.xsuaaTokenFlows = xsuaaTokenFlows;
	}

	public IasXsuaaExchangeBroker(XsuaaServiceConfiguration configuration) {
		this.xsuaaTokenFlows = new XsuaaTokenFlows(
				new XsuaaOAuth2TokenService(new RestTemplate()),
				new XsuaaDefaultEndpoints(configuration.getUaaUrl()),
				new ClientCredentials(configuration.getClientId(), configuration.getClientSecret()));
	}

	public IasXsuaaExchangeBroker(XsuaaServiceConfiguration configuration, OAuth2TokenService tokenService) {
		this.xsuaaTokenFlows = new XsuaaTokenFlows(
				tokenService,
				new XsuaaDefaultEndpoints(configuration.getUaaUrl()),
				new ClientCredentials(configuration.getClientId(), configuration.getClientSecret()));
	}

	@Override
	@Nullable
	public String resolve(HttpServletRequest request) {
		try {
			String oAuth2Token = extractTokenFromRequest(request);

			if (TokenUtil.isXsuaaToken(oAuth2Token)
					|| !TokenUtil.isIasToXsuaaXchangeEnabled()) {
				return oAuth2Token;
			} else if (TokenUtil.isIasToXsuaaXchangeEnabled()) {
				Token token = decodeToken(oAuth2Token);
				return doIasXsuaaXchange(token);
			}
		} catch (ParseException e) {
			logger.error("Couldn't decode the token: {}", e.getMessage());
		}
		return null;
	}

	/**
	 * Request a Xsuaa token using Ias token as a grant.
	 *
	 * @param iasToken
	 *            IAS token
	 * @return encoded Xsuaa token
	 */
	@Nullable
	String doIasXsuaaXchange(Token iasToken) {
		try {
			return xsuaaTokenFlows.userTokenFlow().token(iasToken).execute().getAccessToken();
		} catch (TokenFlowException e) {
			logger.error("Xsuaa token request failed {}", e.getMessage());
		}
		return null;
	}

	/**
	 * Resolves the encoded token to Token class
	 * 
	 * @param oAuth2Token
	 *            encoded token
	 * @return IasToken class
	 * @throws ParseException
	 *             if provided Jwt token couldn't be parsed
	 */
	Token decodeToken(String oAuth2Token) throws ParseException {
		JWT decodedToken = JWTParser.parse(oAuth2Token);
		Jwt jwt = new Jwt(oAuth2Token, decodedToken.getJWTClaimsSet().getIssueTime().toInstant(),
				decodedToken.getJWTClaimsSet().getExpirationTime().toInstant(),
				decodedToken.getHeader().toJSONObject(), decodedToken.getJWTClaimsSet().getClaims());
		return new IasToken(jwt);
	}

	private String extractTokenFromRequest(HttpServletRequest request) {
		String authHeader = request.getHeader(AUTH_HEADER);

		if (authHeader != null && authHeader.toLowerCase().startsWith("bearer")) {
			return authHeader.substring("bearer".length()).trim();
		}
		throw new InvalidBearerTokenException("Invalid authorization header");
	}
}
