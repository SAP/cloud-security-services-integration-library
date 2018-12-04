package com.sap.xs2.security.container;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

public class UserInfoTestUtil {

	public static String createJWT(String pathToTemplate) throws Exception {
		String privateKey = IOUtils.toString(UserInfoTestUtil.class.getResourceAsStream("/privateKey.txt"), StandardCharsets.UTF_8); // PEM format
		String template = IOUtils.toString(UserInfoTestUtil.class.getResourceAsStream(pathToTemplate),StandardCharsets.UTF_8);
		return UserInfoTestUtil.createJWT(template, privateKey,"legacy-token-key");
	}

	public static String createJWT(String claims, String privateKey, String keyId) throws Exception {

		RsaSigner signer = new RsaSigner(privateKey);	
		claims = claims.replace("$exp", "" + (System.currentTimeMillis() / 1000 + 500));

		Map<String, String> headers = new HashMap<>();
		headers.put("kid", keyId);

		org.springframework.security.jwt.Jwt jwt = JwtHelper.encode(claims, signer, headers);

		return jwt.getEncoded();
	}

	public static UserInfo parse(String path, String appName) throws Exception {
		String token = UserInfoTestUtil.createJWT(path);
		return createJwt(token,appName);
	}

	public static  UserInfo loadJwt(String path, String appName) throws Exception {
		String token = IOUtils.resourceToString(path, Charset.forName("UTF-8"));

		return createJwt(token,appName);
	}
	public static UserInfo createJwt(String token, String appName) throws java.text.ParseException {
		JWT parsedJwt = JWTParser.parse(token);
		JWTClaimsSet jwtClaimsSet = parsedJwt.getJWTClaimsSet();
		Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
		Jwt jwt =  new Jwt(parsedJwt.getParsedString(), jwtClaimsSet.getIssueTime().toInstant(), jwtClaimsSet.getExpirationTime().toInstant(), headers, jwtClaimsSet.getClaims());
		return new UserInfo(jwt, appName);
	}
}