/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenFactory;
import org.mockito.Mockito;

public class HybridTokenFactory implements TokenFactory {

	@Override
	public Token create(String jwtToken) {
		return Mockito.mock(AccessToken.class);
	}
}
