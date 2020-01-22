package com.sap.cloud.security.token;

import java.security.Principal;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

public class TokenTestFactory {
	public static Token createFromAccessToken(String accessToken) {
		DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(accessToken);
		return new AbstractToken(decodedJwt) {
			@Override
			public Principal getPrincipal() {
				return null;
			}

			@Override
			public Service getService() {
				return null;
			}

			@Override
			public GrantType getGrantType() {
				return GrantType.CLIENT_CREDENTIALS;
			}
		};
	}
}
