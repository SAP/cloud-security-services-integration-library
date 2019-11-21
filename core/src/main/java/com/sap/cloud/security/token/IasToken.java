package com.sap.cloud.security.token;

import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;

public class IasToken extends AbstractToken {
	public IasToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
	}

	public IasToken(@Nonnull String accessToken) {
		super(accessToken);
	}

	@Override
	public UserPrincipal getPrincipal() {
		return new UserPrincipal() {
			@Override
			public String getFirstName() {
				return getClaimAsString(TokenClaims.IAS.GIVEN_NAME);
			}
			@Override
			public String getLastName() {
				return getClaimAsString(TokenClaims.IAS.FAMILY_NAME);
			}
			@Override
			public String getEmail() {
				return getClaimAsString(TokenClaims.IAS.EMAIL);
			}
			@Override
			public String getUsername() {
				return getClaimAsString(TokenClaims.IAS.USER_NAME);
			}
		};
	}
}
