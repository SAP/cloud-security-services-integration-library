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

public class IasToken extends AbstractToken {
	static final Logger LOGGER = LoggerFactory.getLogger(IasToken.class);

	public IasToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
	}

	public IasToken(@Nonnull String accessToken) {
		super(accessToken);
	}

	@Override
	public Principal getPrincipal() {
		return null;
	}

	@Override
	public Service getService() {
		return Service.IAS;
	}

	@Override
	public GrantType getGrantType() {
		return GrantType.JWT_BEARER;
	}

	@Override
	public List<String> getAudiences() {
		try {
			return super.getAudiences();
		} catch(JsonParsingException e) {
			return Arrays.asList(getClaimAsString(TokenClaims.AUDIENCE));
		}
	}
}
