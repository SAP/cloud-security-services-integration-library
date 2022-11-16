/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

/**
 * Represents a {@link com.sap.cloud.security.token.Token} creation interface.
 */
public interface TokenFactory {

	/**
	 * Returns a token interface for the given JWT token
	 *
	 * @param jwtToken
	 *            the encoded JWT token, e.g. from the Authorization Header
	 * @return the new token instance
	 */
	Token create(String jwtToken);

}
