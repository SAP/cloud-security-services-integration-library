package com.sap.cloud.security.token;

import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import java.security.Principal;
import java.util.List;

public class XsuaaToken extends AbstractToken {

	public XsuaaToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
	}

	public XsuaaToken(@Nonnull String accessToken) {
		super(accessToken);
	}

	public List<String> getScopes() {
		return getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
	}

	@Override
	public Principal getPrincipal() {
		return () -> getClaimAsString(TokenClaims.XSUAA.LOGON_NAME);
	}
}
