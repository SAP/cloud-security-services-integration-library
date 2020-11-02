package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

/**
 * IAS token and XSUAA token exchange and resolution class.
 * Can be used to distinguish between IAS and XSUAA tokens. Controls token exchange between IAS and XSUAA by using xsuaa.iastoxsuaaxchange environment variable flag
 */
public class IasXsuaaExchangeBroker {

	private static final Logger logger = LoggerFactory.getLogger(IasXsuaaExchangeBroker.class);

	private final XsuaaTokenFlows xsuaaTokenFlows;
	private final boolean isIasXsuaaXchangeEnabled;
	private static final String XSUAA_IAS_ENABLED = "XSUAA_IAS_XCHANGE_ENABLED";

	public IasXsuaaExchangeBroker(XsuaaTokenFlows xsuaaTokenFlows) {
		this.xsuaaTokenFlows = xsuaaTokenFlows;
		this.isIasXsuaaXchangeEnabled = resolveIasToXsuaaEnabledFlag();
	}

	/**
	 * Verifies if the provided token is Xsuaa token
	 *
	 * @param encodedJwtToken Encoded token to be checked
	 * @return true if provided token is a XSUAA token
	 */
	public boolean isXsuaaToken(String encodedJwtToken) {
		String claims = Base64JwtDecoder.getInstance().decode(encodedJwtToken).getPayload();
		try {
			JSONObject externalAttributeClaim = new JSONObject(claims)
					.getJSONObject(com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE);
			String externalAttributeValue = externalAttributeClaim
					.getString(com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE_ENHANCER);
			return externalAttributeValue.equalsIgnoreCase("xsuaa");
		} catch (JSONException e) {
			return false;
		}
	}

	/**
	 * Request a Xsuaa token using Ias token as a grant.
	 *
	 * @param iasToken encoded IAS token
	 * @return encoded Xsuaa token
	 */
	@Nullable
	public String getXsuaaToken(String iasToken) {
		try {
			return xsuaaTokenFlows.userTokenFlow().token(iasToken).execute().getAccessToken();
		} catch (TokenFlowException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Checks environment variable 'XSUAA_IAS_XCHANGE_ENABLED' if token exchange
	 * between IAS and XSUAA is enabled. If 'XSUAA_IAS_XCHANGE_ENABLED' is set to 'false'
	 * token exchange is disregarded. Any other value except null is interpreted as true.
	 *
	 * @return returns true if exchange is enabled and false if disabled
	 */
	public boolean isIasXsuaaXchangeEnabled() {
		return isIasXsuaaXchangeEnabled;
	}

	private boolean resolveIasToXsuaaEnabledFlag() {
		String isEnabled = System.getenv(XSUAA_IAS_ENABLED);
		logger.debug("System environment variable {} is set to {}", XSUAA_IAS_ENABLED, isEnabled);
		if (isEnabled != null) {
			if(!isEnabled.equalsIgnoreCase("false")){
				return true;
			}
		}
		return false;
	}

}
