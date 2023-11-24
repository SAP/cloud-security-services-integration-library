/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock;

import com.sap.cloud.security.xsuaa.test.JwtGenerator;

import java.io.IOException;

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

	public static String createJWT(String pathToTemplate, String subdomain, String zid, String keyId) throws IOException {
		JwtGenerator jwtGenerator = new JwtGenerator("sb-java-hello-world", subdomain, zid)
				.setJwtHeaderKeyId(keyId != null ? keyId : "legacy-token-key-" + subdomain);
		return jwtGenerator.createFromTemplate(pathToTemplate).getTokenValue();
	}

}
