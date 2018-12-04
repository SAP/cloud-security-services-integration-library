package com.sap.cloud.security.xsuaa.util;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;

public class JWTUtil {

	public static String createJWT(String clientId) throws Exception {
		String privateKey = IOUtils.toString(JWTUtil.class.getResourceAsStream("/privateKey.txt"), StandardCharsets.UTF_8); // PEM format
		RsaSigner signer = new RsaSigner(privateKey);
		String claims = IOUtils.toString(JWTUtil.class.getResourceAsStream("/claims_template.txt"), StandardCharsets.UTF_8);
		claims = claims.replace("$clientid", clientId);
		claims = claims.replace("$exp", "" + (1531139770997L / 1000 + 1000));
		Jwt jwt = JwtHelper.encode(claims, signer);
		return jwt.getEncoded();
	}

	public static String createJWT(String clientId, String privateKey) throws Exception {
		RsaSigner signer = new RsaSigner(privateKey);
		String claims = IOUtils.toString(JWTUtil.class.getResourceAsStream("/claims_template.txt"), StandardCharsets.UTF_8);
		claims = claims.replace("$clientid", clientId);
		claims = claims.replace("$exp", "" + (System.currentTimeMillis() / 1000 + 5));
		Jwt jwt = JwtHelper.encode(claims, signer);
		return jwt.getEncoded();
	}

	public static String createMultiTenancyJWT(String clientId) throws Exception {
		String privateKey = IOUtils.toString(JWTUtil.class.getResourceAsStream("/privateKey.txt"), StandardCharsets.UTF_8); // PEM format
		return JWTUtil.createMultiTenancyJWT(clientId, privateKey);
	}

	public static String createMultiTenancyJWT(String clientId, String privateKey) throws Exception {
		return JWTUtil.createMultiTenancyJWT(clientId, privateKey, "legacy-Kid");
	}

	public static String createMultiTenancyJWT(String clientId, String privateKey, String keyId) throws Exception {
		RsaSigner signer = new RsaSigner(privateKey);
		String claims = IOUtils.toString(JWTUtil.class.getResourceAsStream("/claims_templateMultiTenancy.txt"), StandardCharsets.UTF_8);
		claims = claims.replace("$clientid", clientId);
		claims = claims.replace("$exp", "" + (System.currentTimeMillis() / 1000 + 5));

		Map<String, String> headers = new HashMap<>();
		headers.put("kid", keyId);

		Jwt jwt = JwtHelper.encode(claims, signer, headers);

		return jwt.getEncoded();
	}

}