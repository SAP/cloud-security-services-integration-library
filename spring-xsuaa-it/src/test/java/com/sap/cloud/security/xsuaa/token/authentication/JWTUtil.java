package com.sap.cloud.security.xsuaa.token.authentication;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;

public class JWTUtil {

	public static String createJWT(String pathToTemplate, String subdomain) throws Exception {
		String privateKey = IOUtils.toString(JWTUtil.class.getResourceAsStream("/privateKey.txt"), StandardCharsets.UTF_8); // PEM format
		String template = IOUtils.toString(JWTUtil.class.getResourceAsStream(pathToTemplate),StandardCharsets.UTF_8);
		return JWTUtil.createJWT(template,subdomain,  privateKey,"legacy-token-key");
	}

	public static String createJWT(String claims, String subdomain, String privateKey, String keyId) throws Exception {

		RsaSigner signer = new RsaSigner(privateKey);	
		claims = claims.replace("$exp", "" + (System.currentTimeMillis() / 1000 + 500));
		claims = claims.replace("$zdn", subdomain);

		Map<String, String> headers = new HashMap<>();
		headers.put("kid", keyId+"-"+subdomain);

		Jwt jwt = JwtHelper.encode(claims, signer, headers);

		return jwt.getEncoded();
	}


}