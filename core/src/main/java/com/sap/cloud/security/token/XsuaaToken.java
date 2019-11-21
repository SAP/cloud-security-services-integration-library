package com.sap.cloud.security.token;

import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import java.util.List;

public class XsuaaToken extends TokenImpl {

	public XsuaaToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
	}

	public XsuaaToken(@Nonnull String accessToken) {
		super(accessToken);
	}

	public List<String> getScopes() {
		return getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
	}

}
