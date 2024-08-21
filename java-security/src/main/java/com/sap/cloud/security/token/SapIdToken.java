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

import static com.sap.cloud.security.token.TokenClaims.SAP_GLOBAL_USER_ID;

/**
 * You can get further token claims from here: {@link TokenClaims}.
 */
public class SapIdToken extends AbstractToken {
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

	/**
	 * Gets the token issuer domain that is required to check trust in the issuing identity service. In multi-tenant or
	 * single-tenant with custom domain scenarios, claim {@link TokenClaims#IAS_ISSUER} must be used for trust checks
	 * instead of claim {@link TokenClaims#ISSUER}. It contains the internal domain of the identity service. External
	 * customer domains are not trusted. <br>
	 * <br>
	 * Use {@link Token#getClaimAsString(String)} with {@link TokenClaims#ISSUER} instead to get the custom domain if
	 * one is used.
	 *
	 * @return value of claim {@link TokenClaims#IAS_ISSUER} if exists, otherwise value of {@link Token#getIssuer()}
	 */
	@Override
	public String getIssuer() {
		if (hasClaim(TokenClaims.IAS_ISSUER)) {
			return getClaimAsString(TokenClaims.IAS_ISSUER);
		}
		return super.getIssuer();
	}

	@Nullable
	public String getCnfX509Thumbprint() {
		return getAttributeFromClaimAsString(TokenClaims.CNF, TokenClaims.CNF_X5T);
	}
}
