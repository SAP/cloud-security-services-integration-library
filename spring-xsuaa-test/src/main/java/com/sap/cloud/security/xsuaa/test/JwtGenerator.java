/**
 * Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.xsuaa.test;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.apache.commons.io.IOUtils;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

/**
 * Create tokens with a fixed private/public key and dummy values. The client ID, identity zone, and scopes are configurable.
 */
public class JwtGenerator {

	public static final Date NO_EXPIRE_DATE = new Date(Long.MAX_VALUE);
	public static final int NO_EXPIRE = Integer.MAX_VALUE;
	public static final String CLIENT_ID = "sb-xsapplication!t895";
	public static final String IDENTITY_ZONE_ID = "uaa"; // must be 'uaa' to make use of mockserver (see XsuaaServiceConfigurationDefault.getTokenKeyUrl)
	private static final String PRIVATE_KEY_FILE = "/privateKey.txt";
	private final String clientId;
	private final String identityZone;
	private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer"; // see TokenImpl.GRANTTYPE_SAML2BEARER;
	private String[] scopes;
	private String userName = "testuser";
	private String jwtHeaderKeyId;
	public Map<String, List<String>> attributes = new HashMap<>();

	/**
	 * @param clientId
	 *            the client ID that will be used for any created token
	 */
	public JwtGenerator(String clientId) {
		this.clientId = clientId;
		this.identityZone = IDENTITY_ZONE_ID;
	}

	public JwtGenerator() {
		this(CLIENT_ID);
	}

	/**
	 * Changes the value of the jwt claim "user_name". The user name is also used for the "email" claim.
	 *
	 * @param userName
	 * @return
	 */
	public JwtGenerator setUserName(String userName) {
		this.userName = userName;
		return this;
	}

	/**
	 * Sets the roles as claim "scope" to the jwt.
	 *
	 * @param scopes
	 *            the scopes that should be part of the token
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator addScopes(String... scopes) {
		this.scopes = scopes;
		return this;
	}

	/**
	 * Adds the attributes as claim "xs.user.attribute" to the jwt.
	 *
	 * @param attributeName
	 *            the attribute name that should be part of the token
	 * @param attributeValues
	 *            the attribute value that should be part of the token
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator addAttribute(String attributeName, String[] attributeValues) {
		List<String> valueList = new ArrayList<>(Arrays.asList(attributeValues));
		attributes.put(attributeName, valueList);
		return this;
	}

	/**
	 * Sets the "keyId" value of the jwt token header.
	 *
	 * @param keyId
	 *            the value of the signed jwt token header "keyId"
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator setJwtHeaderKeyId(String keyId) {
		this.jwtHeaderKeyId = keyId;
		return this;
	}

	/**
	 * Returns an encoded JWT token for the `Authorization` header
	 */
	public String getTokenForAuthorizationHeader() {
		try {
			return "Bearer " + getToken().getTokenValue();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Builds a basic Jwt with the given clientId, userName, scopes and attributes.
	 *
	 * @return jwt
	 */
	public Jwt getToken() throws Exception {
		JWTClaimsSet.Builder claimsSetBuilder = getBasicClaimSet();

		if (scopes != null && scopes.length > 0) {
			claimsSetBuilder.claim("scope", scopes);
		}
		if (attributes.size() > 0) {
			claimsSetBuilder.claim("xs.user.attributes", attributes);
		}
		return createFromClaims(claimsSetBuilder.build());
	}

	public Jwt createFromTemplate(String pathToTemplate) throws Exception {
		String claimsFromTemplate = IOUtils.toString(JwtGenerator.class.getResourceAsStream(pathToTemplate), StandardCharsets.UTF_8);
		String claimsWithReplacements = replacePlaceholders(claimsFromTemplate);
		return createFromClaims(claimsWithReplacements, jwtHeaderKeyId);
	}

	public static Jwt createFromFile(String pathToJwt) throws Exception {
		return convertTokenToOAuthJwt(IOUtils.resourceToString(pathToJwt, Charset.forName("UTF-8")));
	}

	public static Jwt createFromClaims(JWTClaimsSet claimsSet) throws Exception {
		return createFromClaims(claimsSet.toString(), null);
	}

	/**
	 * Builds a basic set of claims
	 *
	 * @return a basic set of claims
	 */
	private JWTClaimsSet.Builder getBasicClaimSet() {
		return new JWTClaimsSet.Builder().issueTime(new Date()).expirationTime(JwtGenerator.NO_EXPIRE_DATE).claim("client_id", clientId).claim("origin", "userIdp").claim("cid", clientId).claim("user_name", userName).claim("user_id", "D012345").claim("email", userName + "@test.org").claim("zid", identityZone).claim("grant_type", GRANT_TYPE);
	}

	private static Jwt createFromClaims(String claims, String jwtHeaderKeyId) throws Exception {
		String token = signAndEncodeToken(claims, jwtHeaderKeyId);
		return convertTokenToOAuthJwt(token);
	}

	private String replacePlaceholders(String claims) {
		claims = claims.replace("$exp", String.valueOf(NO_EXPIRE));
		claims = claims.replace("$clientid", clientId);
		claims = claims.replace("$zid", identityZone);
		claims = claims.replace("$username", userName);

		return claims;
	}

	private static String signAndEncodeToken(String claims, String keyId) throws IOException {
		String privateKey = IOUtils.toString(JwtGenerator.class.getResourceAsStream(PRIVATE_KEY_FILE), StandardCharsets.UTF_8); // PEM format
		RsaSigner signer = new RsaSigner(privateKey);

		Map<String, String> headers = Collections.emptyMap();
		if (keyId != null) {
			headers = new HashMap<>();
			headers.put("kid", keyId);
		}
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
