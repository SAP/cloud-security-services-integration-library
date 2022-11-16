/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.test;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sap.cloud.security.xsuaa.test.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.test.jwt.DecodedJwt;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.springframework.lang.Nullable;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.jwt.Jwt;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import static com.sap.cloud.security.xsuaa.test.JwtGenerator.TokenHeaders.JKU;
import static com.sap.cloud.security.xsuaa.test.JwtGenerator.TokenHeaders.KID;

/**
 * Create tokens with a fixed private/public key and dummy values. The client
 * ID, identity zone, and scopes are configurable.
 */
public class JwtGenerator {

	/**
	 * Do not want to introduce circular reference to spring-xsuaa. duplicate of
	 * com.sap.cloud.security.xsuaa.token.TokenClaims
	 */
	public final class TokenClaims {
		private TokenClaims() {
			throw new IllegalStateException("Utility class");
		}

		static final String CLAIM_XS_USER_ATTRIBUTES = "xs.user.attributes";
		static final String CLAIM_SCOPES = "scope";
		static final String CLAIM_CLIENT_ID = "cid"; // Client Id left for backward compatibility
		static final String CLAIM_AUTHORIZATION_PARTY = "azp";
		static final String CLAIM_USER_NAME = "user_name";
		static final String CLAIM_EMAIL = "email";
		static final String CLAIM_ORIGIN = "origin";
		static final String CLAIM_GRANT_TYPE = "grant_type";
		static final String CLAIM_ZDN = "zdn";
		static final String CLAIM_ZONE_ID = "zid";
		static final String CLAIM_EXTERNAL_ATTR = "ext_attr";
	}

	public final class TokenHeaders {
		private TokenHeaders() {
			throw new IllegalStateException("Utility class");
		}

		static final String JKU = "jku";
		static final String KID = "kid";
	}

	// must match the port defined in XsuaaMockWebServer
	private static final int MOCK_XSUAA_DEFAULT_PORT = 33195;
	private static final String INITIAL_JKU = "null";
	public static final Date NO_EXPIRE_DATE = new GregorianCalendar(2190, 11, 31).getTime();
	public static final int NO_EXPIRE = Integer.MAX_VALUE;
	public static final String CLIENT_ID = "sb-xsapplication!t895";
	public static final String DEFAULT_IDENTITY_ZONE_ID = "uaa";
	private static final String PRIVATE_KEY_FILE = "/spring-xsuaa-privateKey.txt";
	// see XsuaaToken.GRANTTYPE_SAML2BEARER
	private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer";

	private final String azp;
	private final String identityZoneId;
	private final String subdomain;

	private String jku = INITIAL_JKU;
	private String[] scopes;
	private String userName = "testuser";
	private String jwtHeaderKeyId = "legacy-token-key";
	private int port;
	private Map<String, List<String>> attributes = new HashMap<>();
	private Map<String, Object> customClaims = new LinkedHashMap();
	private boolean deriveAudiences = false;

	/**
	 * Specifies authorization party of the JWT token claim.
	 *
	 * @param clientId
	 *            the XSUAA client id, e.g. sb-applicationName!t123, defines the
	 *            value of the JWT token claims "azp" and "cid". A token is
	 *            considered to be valid when it matches the "xsuaa.clientid" xsuaa
	 *            service configuration (VCAP_SERVICES).
	 */
	public JwtGenerator(String clientId) {
		this(clientId, MOCK_XSUAA_DEFAULT_PORT);
	}

	/**
	 * Specifies authorization party of the JWT token claim.
	 *
	 * @param clientId
	 *            the XSUAA client id, e.g. sb-applicationName!t123, defines the
	 *            value of the JWT token claims "azp" and "cid". A token is
	 *            considered to be valid when it matches the "xsuaa.clientid" xsuaa
	 *            service configuration (VCAP_SERVICES).
	 * @param port
	 *            the port that is used to connect to the XSUAA mock web server.
	 */
	public JwtGenerator(String clientId, int port) {
		this(clientId, "", DEFAULT_IDENTITY_ZONE_ID);
		this.port = port;
	}

	/**
	 * Overwrites some default values of the JWT token claims.
	 *
	 * @param clientId
	 *            the XSUAA client id, e.g. sb-applicationName!t123, defines the
	 *            value of the JWT token claims "azp" and "cid". A token is
	 *            considered to be valid when it matches the "xsuaa.clientid" xsuaa
	 *            service configuration (VCAP_SERVICES).
	 * @param subdomain
	 *            of the subaccount, e.g. d012345trial. This defines the value of
	 *            the claim "zdn". Furthermore the identity-zone-id claim "zid" is
	 *            derived from that.
	 */
	public JwtGenerator(String clientId, String subdomain) {
		this(clientId, subdomain, subdomain + "-id");
	}

	public JwtGenerator(String clientId, String subdomain, String identityZoneId) {
		this.azp = clientId;
		this.subdomain = subdomain;
		this.identityZoneId = identityZoneId;
		this.port = MOCK_XSUAA_DEFAULT_PORT;
	}

	/**
	 *
	 * @param port
	 *            the port that is used to connect to the XSUAA mock web server.
	 */
	public JwtGenerator(int port) {
		this(CLIENT_ID, port);
	}

	public JwtGenerator() {
		this(CLIENT_ID);
	}

	/**
	 * Changes the value of the jwt claim "user_name". The user name is also used
	 * for the "email" claim.
	 *
	 * @param userName
	 *            the user name
	 * @return the JwtGenerator itself
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
	 * Sets the keyId value as "kid" header to the jwt.
	 *
	 * @param keyId
	 *            the value of the signed jwt token header "kid"
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator setJwtHeaderKeyId(String keyId) {
		this.jwtHeaderKeyId = keyId;
		return this;
	}

	/**
	 * Adds additional custom claims.
	 *
	 * @param customClaims
	 *            the claims that should be part of the token
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator addCustomClaims(Map<String, Object> customClaims) {
		this.customClaims.putAll(customClaims);
		return this;
	}

	/**
	 * Derives audiences claim ("aud") from scopes. For example in case e.g.
	 * "xsappid.scope".
	 *
	 * @param shallDeriveAudiences
	 *            if true, audiences are automatically set
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator deriveAudiences(boolean shallDeriveAudiences) {
		this.deriveAudiences = shallDeriveAudiences;
		return this;
	}

	/**
	 * Returns an encoded JWT token for the "Authorization" REST header
	 *
	 * @return jwt token String with "Bearer " prefix
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
	 * Sets the url which is used to retrieve the verification keys
	 *
	 * @param jku
	 *            the url to retrieve the keys
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator setJku(String jku) {
		this.jku = jku;
		return this;
	}

	/**
	 * Sets the port which is used to retrieve the verification keys
	 *
	 * @param port
	 *            the port that is used to connect to the XSUAA mock web server.
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator setPort(int port) {
		this.port = port;
		return this;
	}

	/**
	 * Builds a basic Jwt with the given azp, userName, scopes, user attributes
	 * claims and the keyId header.
	 *
	 * @return jwt
	 */
	public Jwt getToken() {
		JWTClaimsSet.Builder claimsSetBuilder = getBasicClaimSet();

		if (scopes != null && scopes.length > 0) {
			claimsSetBuilder.claim(TokenClaims.CLAIM_SCOPES, scopes);
			if (deriveAudiences) {
				claimsSetBuilder.audience(deriveAudiencesFromScopes(scopes));
			}
		}
		if (attributes.size() > 0) {
			claimsSetBuilder.claim(TokenClaims.CLAIM_XS_USER_ATTRIBUTES, attributes);
		}
		for (Map.Entry<String, Object> customClaim : customClaims.entrySet()) {
			claimsSetBuilder.claim(customClaim.getKey(), customClaim.getValue());
		}
		return createFromClaims(claimsSetBuilder.build().toString(), getHeaderMap(jwtHeaderKeyId, getOrCreateJku()));
	}

	private String getOrCreateJku() {
		if (INITIAL_JKU.equals(jku)) {
			String subdomainPart = subdomain != null && !subdomain.equals("") ? "/" + subdomain : "";
			return "http://localhost:" + port + subdomainPart + "/token_keys";
		}
		return jku;
	}

	private List<String> deriveAudiencesFromScopes(String[] scopes) {
		List<String> audiences = new ArrayList<>();
		for (String scope : scopes) {
			if (scope.contains(".")) {
				String aud = scope.substring(0, scope.indexOf('.'));
				if (aud.isEmpty() || audiences.contains(aud)) {
					break;
				}
				audiences.add(aud);
			}
		}
		return audiences;
	}

	/**
	 * Creates a Jwt from a template file, which contains the claims. Optionally,
	 * configure the "keyId" header via {@link #setJwtHeaderKeyId(String)}
	 *
	 * This replaces these placeholders:
	 * <ul>
	 * <li>"$exp" with a date, that will not expire</li>
	 * <li>"$azp" with the configured client id {@link #JwtGenerator(String)}</li>
	 * <li>"$zdn" with the configured subdomain
	 * {@link #JwtGenerator(String, String)}</li>
	 * <li>"$zid" with "uaa" or with the configured subdomain
	 * {@link #JwtGenerator(String,String)}</li>
	 * <li>"$username" with the configured user name {@link #setUserName(String)}
	 * </li>
	 * </ul>
	 *
	 * @param pathToTemplate
	 *            classpath resource
	 * @return a jwt
	 * @throws IOException
	 *             in case the template file can not be read
	 */
	public Jwt createFromTemplate(String pathToTemplate) throws IOException {
		String claimsFromTemplate = IOUtils.resourceToString(pathToTemplate, StandardCharsets.UTF_8);
		String claimsWithReplacements = replacePlaceholders(claimsFromTemplate);
		return createFromClaims(claimsWithReplacements, getHeaderMap(jwtHeaderKeyId, getOrCreateJku()));
	}

	/**
	 * Creates a Jwt from a file, which contains an encoded Jwt token.
	 *
	 * @param pathToJwt
	 *            classpath resource
	 * @return a jwt
	 * @throws IOException
	 *             in case the template file can not be read
	 */
	public static Jwt createFromFile(String pathToJwt) throws IOException {
		return convertTokenToOAuthJwt(IOUtils.resourceToString(pathToJwt, Charset.forName("UTF-8")));
	}

	/**
	 * Creates an individual Jwt based on the provided set of claims.
	 *
	 * @param claimsSet
	 *            that can be created with Nimbus JOSE + JWT JWTClaimsSet.Builder
	 * @return a jwt
	 */
	public static Jwt createFromClaims(JWTClaimsSet claimsSet) {
		return createFromClaims(claimsSet.toString(), Collections.EMPTY_MAP);
	}

	/**
	 * Creates an individual Jwt based on the provided set of claims.
	 *
	 * @param claimsSet
	 *            that can be created with Nimbus JOSE + JWT JWTClaimsSet.Builder
	 * @param tokenHeaders
	 *            that contains a set of headers that should be included in the
	 *            final jwt.
	 * @return a jwt
	 */
	public static Jwt createFromClaims(JWTClaimsSet claimsSet, Map<String, String> tokenHeaders) {
		return createFromClaims(claimsSet.toString(), tokenHeaders);
	}

	/**
	 * Builds a basic set of claims
	 *
	 * @return a basic set of claims
	 */
	public JWTClaimsSet.Builder getBasicClaimSet() {
		return new JWTClaimsSet.Builder()
				.issueTime(new Date())
				.expirationTime(JwtGenerator.NO_EXPIRE_DATE)
				.claim(TokenClaims.CLAIM_CLIENT_ID, azp) // Client Id left for backward compatibility
				.claim(TokenClaims.CLAIM_AUTHORIZATION_PARTY, azp)
				.claim(TokenClaims.CLAIM_ORIGIN, "userIdp")
				.claim(TokenClaims.CLAIM_USER_NAME, userName)
				.claim(TokenClaims.CLAIM_EMAIL, userName + "@test.org")
				.claim(TokenClaims.CLAIM_ZDN, subdomain)
				.claim(TokenClaims.CLAIM_ZONE_ID, identityZoneId)
				.claim(TokenClaims.CLAIM_EXTERNAL_ATTR, new ExternalAttrClaim())
				.claim(TokenClaims.CLAIM_GRANT_TYPE, GRANT_TYPE);
	}

	/**
	 * Builds a basic set of claims
	 *
	 * @return a basic set of claims
	 */
	public Map<String, String> getBasicHeaders() {
		return getHeaderMap(jwtHeaderKeyId, getOrCreateJku());
	}

	private static Jwt createFromClaims(String claims, Map<String, String> headers) {
		String token = signAndEncodeToken(claims, headers);
		return convertTokenToOAuthJwt(token);
	}

	private static Map<String, String> getHeaderMap(String jwtHeaderKeyId, String jwtKeyUrl) {
		Map<String, String> headers = new HashMap<>();
		if (jwtHeaderKeyId != null) {
			headers.put(KID, jwtHeaderKeyId);
		}
		if (jwtKeyUrl != null) {
			headers.put(JKU, jwtKeyUrl);
		}
		return headers;
	}

	private String replacePlaceholders(String claims) {
		claims = claims.replace("$exp", String.valueOf(NO_EXPIRE));
		claims = claims.replace("$clientid", azp); // Client Id left for backward compatibility
		claims = claims.replace("$azp", azp);
		claims = claims.replace("$zdn", subdomain);
		claims = claims.replace("$zid", identityZoneId);
		claims = claims.replace("$username", userName);

		return claims;
	}

	private static String signAndEncodeToken(String claims, Map<String, String> tokenHeaders) {
		RsaSigner signer = new RsaSigner(readPrivateKeyFromFile());

		org.springframework.security.jwt.Jwt jwt = JwtHelper.encode(claims, signer, tokenHeaders);

		return jwt.getEncoded();
	}

	protected static String readPrivateKeyFromFile() {
		String privateKey;
		try {
			privateKey = IOUtils.resourceToString(PRIVATE_KEY_FILE, StandardCharsets.UTF_8); // PEM format
		} catch (IOException e) {
			throw new IllegalStateException("privateKey could not be read from " + PRIVATE_KEY_FILE, e);
		}
		return privateKey;
	}

	@Nullable
	public static Jwt convertTokenToOAuthJwt(String token) {
		return parseJwt(decodeJwt(token));
	}

	private static Jwt parseJwt(DecodedJwt decodedJwt) {
		JSONObject payload = new JSONObject(decodedJwt.getPayload());
		JSONObject header = new JSONObject(decodedJwt.getHeader());
		return new Jwt(decodedJwt.getEncodedToken(), Instant.ofEpochSecond(payload.optLong("iat")),
				Instant.ofEpochSecond(payload.getLong("exp")),
				header.toMap(), payload.toMap());
	}

	static DecodedJwt decodeJwt(String encodedJwtToken) {
		return Base64JwtDecoder.getInstance().decode(encodedJwtToken);
	}

	protected class ExternalAttrClaim {
		public String zdn = subdomain;
		public String enhancer = "XSUAA";
	}
}
