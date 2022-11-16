/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock;

import java.io.IOException;

import com.sap.cloud.security.xsuaa.test.JwtGenerator;

public class JWTUtil {

	private JWTUtil() {
		// hide public one
	}

	public static String createJWT(String pathToTemplate, String subdomain) throws IOException {
		return JWTUtil.createJWT(pathToTemplate, subdomain, "legacy-token-key-" + subdomain);
	}

	public static String createJWT(String pathToTemplate, String subdomain, String keyId) throws IOException {
		JwtGenerator jwtGenerator = new JwtGenerator("sb-java-hello-world", subdomain)
				.setJwtHeaderKeyId(keyId);
		return jwtGenerator.createFromTemplate(pathToTemplate).getTokenValue();
	}

}
