package com.sap.cloud.security.xsuaa.mock;

import com.sap.cloud.security.xsuaa.test.JwtGenerator;

public class JWTUtil {

	public static String createJWT(String pathToTemplate, String subdomain) throws Exception {
		return JWTUtil.createJWT(pathToTemplate, subdomain, "legacy-token-key-" + subdomain, null);
	}

	public static String createJWT(String pathToTemplate, String subdomain, String jku) throws Exception {
		return JWTUtil.createJWT(pathToTemplate, subdomain, "legacy-token-key-" + subdomain, jku);
	}

	public static String createJWT(String pathToTemplate, String subdomain, String keyId, String jku) throws Exception {
		JwtGenerator jwtGenerator = new JwtGenerator("sb-java-hello-world", subdomain)
				.setJwtHeaderKeyId(keyId).setJku(jku);
		return jwtGenerator.createFromTemplate(pathToTemplate).getTokenValue();
	}
}
