package com.sap.cloud.security.token;

import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;

import java.security.Principal;

public class IasToken extends AbstractToken {
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
}
