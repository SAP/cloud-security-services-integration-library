/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token.authentication;

import com.nimbusds.jwt.JWT;

/**
 * Responsible to extract information out of the token and provide it to the
 * JwtDecoder.
 */
public interface TokenInfoExtractor {

	String getJku(JWT jwt);

	String getKid(JWT jwt);

	String getUaaDomain(JWT jwt);
}
