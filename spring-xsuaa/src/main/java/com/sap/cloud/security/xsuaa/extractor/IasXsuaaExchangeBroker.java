package com.sap.cloud.security.xsuaa.extractor;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import java.text.ParseException;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE_ENHANCER;

/**
 * IAS token and XSUAA token exchange and resolution class. Can be used to
 * distinguish between IAS and XSUAA tokens. Controls token exchange between IAS
 * and XSUAA by using IAS_XSUAA_XCHANGE_ENABLED environment variable flag
 */
public class IasXsuaaExchangeBroker implements BearerTokenResolver {

	private static final Logger logger = LoggerFactory.getLogger(IasXsuaaExchangeBroker.class);

	private final XsuaaTokenFlows xsuaaTokenFlows;
	private final boolean isIasXsuaaXchangeEnabled = resolveIasToXsuaaEnabledFlag();
	private static final String AUTH_HEADER = "Authorization";
	private static final String IAS_XSUAA_ENABLED = "IAS_XSUAA_XCHANGE_ENABLED";

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

			if (isXsuaaToken(oAuth2Token)
					|| !isIasXsuaaXchangeEnabled()) {
				return oAuth2Token;
			} else if (isIasXsuaaXchangeEnabled()) {
				Token token = decodeToken(oAuth2Token);
				return doIasXsuaaXchange(token);
			}
		} catch (ParseException e) {
			logger.error("Couldn't decode the token: {}", e.getMessage());
		}
		return null;
	}

	/**
	 * Verifies if the provided token is Xsuaa token
	 *
	 * @param encodedJwtToken
	 *            Encoded token to be checked
	 * @return true if provided token is a XSUAA token
	 */
	public boolean isXsuaaToken(String encodedJwtToken) {
		String claims = Base64JwtDecoder.getInstance().decode(encodedJwtToken).getPayload();
		try {
			JSONObject externalAttributeClaim = new JSONObject(claims)
					.getJSONObject(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE);
			String externalAttributeValue = externalAttributeClaim
					.getString(EXTERNAL_ATTRIBUTE_ENHANCER);
			return externalAttributeValue.equalsIgnoreCase("xsuaa");
		} catch (JSONException e) {
			return false;
		}
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
	 * Checks value of environment variable 'IAS_XSUAA_XCHANGE_ENABLED'. This value
	 * determines, whether token exchange between IAS and XSUAA is enabled. If
	 * IAS_XSUAA_XCHANGE_ENABLED is not provided or with an empty value or with
	 * value = false, then token exchange is disabled. Any other values are
	 * interpreted as true.
	 *
	 * @return returns true if exchange is enabled and false if disabled
	 */
	boolean isIasXsuaaXchangeEnabled() {
		return isIasXsuaaXchangeEnabled;
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

	private boolean resolveIasToXsuaaEnabledFlag() {
		String isEnabled = System.getenv(IAS_XSUAA_ENABLED);
		logger.debug("System environment variable {} is set to {}", IAS_XSUAA_ENABLED, isEnabled);
		if (isEnabled != null) {
			return !isEnabled.equalsIgnoreCase("false");
		}
		return false;
	}

	private String extractTokenFromRequest(HttpServletRequest request) {
		String authHeader = request.getHeader(AUTH_HEADER);

		if ((authHeader.toLowerCase().startsWith("bearer"))) {
			return authHeader.substring("bearer".length()).trim();
		}
		return null;
	}
}
