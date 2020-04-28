package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;

import static com.sap.cloud.security.token.TokenClaims.SAP_GLOBAL_USER_ID;

/**
 * You can get further token claims from here: {@link TokenClaims}.
 */
public class SapIdToken extends AbstractToken {

	private static final Logger LOGGER = LoggerFactory.getLogger(SapIdToken.class);

	public SapIdToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
		LOGGER.warn("IAS Service is not yet supported!");
	}

	public SapIdToken(@Nonnull String idToken) {
		super(idToken);
		LOGGER.warn("IAS Service is not yet supported!");
	}

	@Override
	public Principal getPrincipal() {
		return createPrincipalByName(getClaimAsString(SAP_GLOBAL_USER_ID));
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
