package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;

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

	public SapIdToken(@Nonnull String idToken) {
		super(idToken);
	}

	@Override
	public Principal getPrincipal() {
		// TODO IAS: should return SAP User ID (guid) if available in id token
		return null;
	}

	@Override
	public Service getService() {
		return Service.IAS;
	}

	@Override
	public Set<String> getAudiences() {
		try {
			return super.getAudiences();
		} catch (JsonParsingException e) {
			final Set<String> audiences = new LinkedHashSet<>();
			audiences.add(getClaimAsString(TokenClaims.AUDIENCE));
			return audiences;
		}
	}
}
