package com.sap.cloud.security.xsuaa.mock;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;

public class JWTUtil {

	public static String createJWT(String pathToTemplate, String subdomain) throws Exception {
		String privateKey = IOUtils.resourceToString("/privateKey.txt", StandardCharsets.UTF_8); // PEM format
		String template = IOUtils.resourceToString(pathToTemplate, StandardCharsets.UTF_8); // PEM format
		return JWTUtil.createJWT(template, subdomain, privateKey, "legacy-token-key-" + subdomain);
	}

	public static String createJWT(String pathToTemplate, String subdomain, String keyId) throws Exception {
		String privateKey = IOUtils.resourceToString("/privateKey.txt", StandardCharsets.UTF_8); // PEM format
		String template = IOUtils.resourceToString(pathToTemplate, StandardCharsets.UTF_8); // PEM format
		return JWTUtil.createJWT(template, subdomain, privateKey, keyId);
	}

	public static String createJWT(String claims, String subdomain, String privateKey, String keyId) throws Exception {
		RsaSigner signer = new RsaSigner(privateKey);
		claims = claims.replace("$exp", "" + (System.currentTimeMillis() / 1000 + 500));
		claims = claims.replace("$zdn", subdomain);

		Map<String, String> headers = new HashMap<>();
		headers.put("kid", keyId);

		Jwt jwt = JwtHelper.encode(claims, signer, headers);

		return jwt.getEncoded();
	}

}