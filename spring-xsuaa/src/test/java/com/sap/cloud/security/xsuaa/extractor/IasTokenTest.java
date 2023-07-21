/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Arrays;
import java.util.Date;

import static com.sap.cloud.security.token.TokenClaims.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

class IasTokenTest {

	private JWTClaimsSet.Builder claimsSetBuilder = null;
	private final String appTid = "app-tid";
	private final String zoneId = "zone-id";
	private static final String USER_ID = "test-user-id";
	private static final String USER_NAME_VALUE = "testUser";

	@BeforeEach
	void setUp() {
		claimsSetBuilder = new JWTClaimsSet.Builder()
				.issueTime(new Date())
				.expirationTime(JwtGenerator.NO_EXPIRE_DATE)
				.claim(SAP_GLOBAL_USER_ID, USER_ID)
				.claim(SAP_GLOBAL_APP_TID, appTid)
				.claim(SAP_GLOBAL_ZONE_ID, zoneId)
				.claim(USER_NAME, USER_NAME_VALUE)
				.claim(AUTHORIZATION_PARTY, "client-id")
				.claim(AUDIENCE, Arrays.asList("aud1", "aud2"));
	}

	@Test
	void checkIasTokenTest() {
		IasToken token = createToken(claimsSetBuilder);

		assertThat(token.getClientId(), is("client-id"));
		assertThat(token.getAppTid(), is(appTid));
		assertThat(token.getExpiration(), is(JwtGenerator.NO_EXPIRE_DATE.toInstant()));
		assertThat(token.getAudiences().size(), is(2));
		assertThat(token.getService(), is(Service.IAS));
		assertThat(token.getTokenValue(), not(""));
		assertThat(token.getTokenValue(), notNullValue());
		assertThat(token.isExpired(), is(false));
		assertThat(token.hasClaim(EMAIL), is(false));
		assertThat(token.hasClaim(SAP_GLOBAL_APP_TID), is(true));
	}

	@Test
	void checkAppTidFallback() {
		JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
				.claim(SAP_GLOBAL_ZONE_ID, zoneId)
				.expirationTime(JwtGenerator.NO_EXPIRE_DATE);
		IasToken token = createToken(claimsSetBuilder);

		assertThat(token.getAppTid(), is(zoneId));
	}

	private IasToken createToken(JWTClaimsSet.Builder claimsBuilder) {
		Jwt jwt = JwtGenerator.createFromClaims(claimsBuilder.build());
		return new IasToken(jwt);
	}
}