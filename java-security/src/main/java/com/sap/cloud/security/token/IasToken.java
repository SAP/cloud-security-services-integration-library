package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;

import java.security.Principal;

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
}
