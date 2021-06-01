/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
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

	@Nullable
	public String getCnfX509Thumbprint() {
		return getAttributeFromClaimAsString(TokenClaims.CNF, TokenClaims.CNF_X509_THUMBPRINT);
	}
}
