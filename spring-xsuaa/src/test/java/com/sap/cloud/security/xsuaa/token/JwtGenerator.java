package com.sap.cloud.security.xsuaa.token;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import com.sap.xs2.security.container.UserInfoTestUtil;
import org.apache.commons.io.IOUtils;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

public class JwtGenerator {
	public static final Date NO_EXPIRE = new Date(Long.MAX_VALUE);

	public static Jwt createFromTemplate(String pathToTemplate) throws Exception {
		String claims = IOUtils.toString(UserInfoTestUtil.class.getResourceAsStream(pathToTemplate), StandardCharsets.UTF_8);
		return createFromClaims(claims);
	}

	public static Jwt createFromFile(String pathToJwt) throws Exception {
		return convertTokenToOAuthJwt(IOUtils.resourceToString(pathToJwt, Charset.forName("UTF-8")));
	}

	public static Jwt createFromClaims(JWTClaimsSet claimsSet) throws Exception {
		return createFromClaims(claimsSet.toString());
	}

	private static Jwt createFromClaims(String claims) throws Exception {
		String privateKey = IOUtils.toString(UserInfoTestUtil.class.getResourceAsStream("/privateKey.txt"), StandardCharsets.UTF_8); // PEM format
		String token = createToken(claims, privateKey, "legacy-samlUserInfo-key");
		return convertTokenToOAuthJwt(token);
	}

	private static String createToken(String claims, String privateKey, String keyId) throws Exception {
		RsaSigner signer = new RsaSigner(privateKey);
		claims = claims.replace("$exp", "" + (System.currentTimeMillis() / 1000 + 500));

		Map<String, String> headers = new HashMap<>();
		headers.put("kid", keyId);

		org.springframework.security.jwt.Jwt jwt = JwtHelper.encode(claims, signer, headers);

		return jwt.getEncoded();
	}

	public static Jwt convertTokenToOAuthJwt(String token) throws java.text.ParseException {
		JWT parsedJwt = JWTParser.parse(token);
		JWTClaimsSet jwtClaimsSet = parsedJwt.getJWTClaimsSet();
		Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
		Jwt jwt = new Jwt(parsedJwt.getParsedString(), jwtClaimsSet.getIssueTime().toInstant(), jwtClaimsSet.getExpirationTime().toInstant(), headers, jwtClaimsSet.getClaims());
		return jwt;
	}
}
