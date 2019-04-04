package com.sap.cloud.security.xsuaa.mock;

import com.sap.cloud.security.xsuaa.test.JwtGenerator;

public class JWTUtil {

	public static String createJWT(String pathToTemplate, String subdomain) throws Exception {
		return JWTUtil.createJWT(pathToTemplate, subdomain, "legacy-token-key-" + subdomain);
	}

	public static String createJWT(String pathToTemplate, String subdomain, String keyId) throws Exception {
		JwtGenerator jwtGenerator = new JwtGenerator("sb-java-hello-world", subdomain)
				.setJwtHeaderKeyId(keyId);
		return jwtGenerator.createFromTemplate(pathToTemplate).getTokenValue();
	}

}