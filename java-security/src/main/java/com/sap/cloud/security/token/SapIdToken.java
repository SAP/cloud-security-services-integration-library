/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.Principal;

import static com.sap.cloud.security.token.TokenClaims.ISSUER;
import static com.sap.cloud.security.token.TokenClaims.SAP_GLOBAL_USER_ID;

/**
 * You can get further token claims from here: {@link TokenClaims}.
 */
public class SapIdToken extends AbstractToken {
	static final String IAS_ISSUER = "ias_iss";

	public SapIdToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
	}

	public SapIdToken(@Nonnull String idToken) {
		super(idToken);
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
	public String getIssuer() {
		if (hasClaim(IAS_ISSUER)) {
			return getClaimAsString(IAS_ISSUER);
		}
		return super.getIssuer();
	}

	/**
	 * In case of active custom domains this returns the identifier for the Issuer
	 * of the token. Its a URL that contains scheme, host with custom domain, and
	 * optionally, port number and path components. This one is irrelevant for token
	 * validation.
	 *
	 * @return the custom domain issuer.
	 */
	String getCustomIssuer() {
		if (hasClaim(IAS_ISSUER)) {
			return getClaimAsString(ISSUER);
		}
		return null;
	}

	@Nullable
	public String getCnfX509Thumbprint() {
		return getAttributeFromClaimAsString(TokenClaims.CNF, TokenClaims.CNF_X5T);
	}
}
