package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;

import java.security.Principal;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * You can get further token claims from here: {@link TokenClaims}.
 */
public class SapIdToken extends AbstractToken {
	static final Logger LOGGER = LoggerFactory.getLogger(SapIdToken.class);

	public SapIdToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
	}

	public SapIdToken(@Nonnull String accessToken) {
		super(accessToken);
	}

	@Override
	public Principal getPrincipal() {
		// TODO IAS: should return SAP User ID (guid)
		throw new UnsupportedOperationException(
				"getPrincipal() is not yet supported for tokens of service " + getService() + ".");
	}

	@Override
	public Service getService() {
		return Service.IAS;
	}

	@Override
	public List<String> getAudiences() {
		try {
			return super.getAudiences();
		} catch (JsonParsingException e) {
			return Arrays.asList(getClaimAsString(TokenClaims.AUDIENCE));
		}
	}
}
