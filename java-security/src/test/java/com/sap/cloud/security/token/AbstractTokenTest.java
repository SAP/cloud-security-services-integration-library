/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import org.apache.commons.io.IOUtils;
import org.assertj.core.util.Sets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Stream;

import static com.sap.cloud.security.token.TokenClaims.*;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.CLIENT_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

class AbstractTokenTest {

	private final String jwtString;
	private final Token cut;

	public AbstractTokenTest() throws IOException {
		jwtString = IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		cut = new AbstractToken(jwtString) {
			@Override
			public Principal getPrincipal() {
				return null;
			}

			@Override
			public Service getService() {
				return null;
			}
		};
	}

	@Test
	void getHeaderParameterAsString() {
		assertThat(cut.getHeaderParameterAsString("alg")).isEqualTo("RS256");
	}

	@Test
	void containsClaim() {
		assertThat(cut.hasClaim("notContained")).isFalse();
		assertThat(cut.hasClaim("grant_type")).isTrue();
	}

	@Test
	void getClaimAsString() {
		assertThat(cut.getClaimAsString("zid")).isEqualTo("uaa");
	}

	@Test
	void getClaimAsStringList() {
		assertThat(cut.getClaimAsStringList("aud")).containsExactly("uaa", "sap_osb");
	}

	@Test
	void getClaimAsStringList_unknownClaim_emptyList() {
		assertThat(cut.getClaimAsStringList("anything")).isEqualTo(Collections.emptyList());
	}

	@Test
	void getExpiration() {
		assertThat(cut.getExpiration()).isEqualTo(Instant.ofEpochSecond(1572060769L));
	}

	@Test
	void tokenWithExpirationInTheFuture_isNotExpired() {
		AbstractToken doesNotExpireSoon = new MockTokenBuilder().withExpiration(MockTokenBuilder.NO_EXPIRE_DATE)
				.build();
		when(doesNotExpireSoon.isExpired()).thenCallRealMethod();

		assertThat(doesNotExpireSoon.isExpired()).isFalse();
	}

	@Test
	void tokenWithExpirationInThePast_isExpired() {
		assertThat(cut.isExpired()).isTrue();
	}

	@Test
	void tokenWithoutExpirationDate_isExpired() {
		AbstractToken tokenWithoutExpiration = new MockTokenBuilder().withExpiration(null).build();
		when(tokenWithoutExpiration.isExpired()).thenCallRealMethod();

		assertThat(tokenWithoutExpiration.isExpired()).isTrue();
	}

	@Test
	void tokenWithLongExpiration_isNotExpired() {
		AbstractToken tokenWithNoExpiration = new MockTokenBuilder().withExpiration(MockTokenBuilder.NO_EXPIRE_DATE)
				.build();
		when(tokenWithNoExpiration.isExpired()).thenCallRealMethod();

		assertThat(tokenWithNoExpiration.isExpired()).isFalse();
	}

	@Test
	void getNotBefore_notContained_shouldBeNull() {
		assertThat(String.valueOf(cut.getNotBefore().toEpochMilli())).startsWith("1572017569"); // consider iat
	}

	@Test
	void getTokenValue() {
		assertThat(cut.getTokenValue()).isEqualTo(jwtString);
	}

	@Test
	void getJsonObject() {
		JsonObject externalAttributes = cut.getClaimAsJsonObject(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE);
		assertThat(externalAttributes.getAsString(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE_ENHANCER)).isEqualTo("XSUAA");
	}

	@Test
	void getJsonObject_claimsIsNotAnObject_throwsException() {
		assertThatThrownBy(() -> cut.getClaimAsJsonObject("client_id")).isInstanceOf(JsonParsingException.class);
	}

	@Test
	void getJsonObject_claimsDoesNotExist_isNull() {
		assertThat(cut.getClaimAsJsonObject("doesNotExist")).isNull();
	}

	@Test
	void toString_doesNotContainEncodedToken() {
		assertThat(cut.toString()).doesNotContain(cut.getTokenValue());
	}

	@Test
	void toString_containsTokenContent() {
		assertThat(cut.toString())
				.contains(cut.getHeaderParameterAsString(TokenHeader.JWKS_URL))
				.contains(cut.getHeaderParameterAsString(TokenHeader.KEY_ID))
				.contains(cut.getAudiences())
				.contains(cut.getClientId())
				.contains(cut.getClaimAsString(TokenClaims.XSUAA.GRANT_TYPE))
				.contains(cut.getClaimAsStringList(TokenClaims.XSUAA.SCOPES));
	}

	@Test
	void isXsuaaToken() {
		assertThat(((AbstractToken) cut).isXsuaaToken()).isTrue();
	}

	@Test
	void getTenantId() {
		AbstractToken token = Mockito.mock(AbstractToken.class);
		when(token.hasClaim(SAP_GLOBAL_APP_TID)).thenReturn(true);
		when(token.getClaimAsString(SAP_GLOBAL_ZONE_ID)).thenReturn("zone-id");
		when(token.getClaimAsString(SAP_GLOBAL_APP_TID)).thenReturn("app-tid");
		when(token.getAppTid()).thenCallRealMethod();
		assertThat(token.getAppTid()).isEqualTo("app-tid");

		when(token.hasClaim(SAP_GLOBAL_APP_TID)).thenReturn(false);
		when(token.getClaimAsString(SAP_GLOBAL_ZONE_ID)).thenReturn("zone-id");
		assertThat(token.getAppTid()).isEqualTo("zone-id");
	}

	@ParameterizedTest
	@ValueSource(strings = { "cid", "", "    " })
	void getClientIdWithCidTest(String cid) throws InvalidTokenException {
		AbstractToken token = Mockito.mock(AbstractToken.class);
		when(token.getAudiences()).thenReturn(Collections.emptySet());
		when(token.getClaimAsString(AUTHORIZATION_PARTY)).thenReturn(null);
		when(token.getClaimAsString(CLIENT_ID)).thenReturn(cid);
		when(token.hasClaim(CLIENT_ID)).thenReturn(!cid.trim().isEmpty());
		when(token.getClientId()).thenCallRealMethod();
		try {
			assertThat(token.getClientId()).isEqualTo(cid);
		} catch (InvalidTokenException e) {
			assertThatThrownBy(() -> token.getClientId()).isExactlyInstanceOf(InvalidTokenException.class);
		}
	}

	@ParameterizedTest
	@MethodSource("clientIdTestArguments")
	void getClientIdTest(String azp, Set<String> aud, String expectedClientId,
			Class<InvalidTokenException> expectedException) throws InvalidTokenException {
		AbstractToken token = Mockito.mock(AbstractToken.class);
		when(token.getAudiences()).thenReturn(aud);
		when(token.getClaimAsString(AUTHORIZATION_PARTY)).thenReturn(azp);
		when(token.getClientId()).thenCallRealMethod();

		if (expectedException != null) {
			assertThatThrownBy(() -> token.getClientId()).isExactlyInstanceOf(expectedException);
		} else {
			assertThat(token.getClientId()).isEqualTo(expectedClientId);
		}
	}

	private static Stream<Arguments> clientIdTestArguments() {
		return Stream.of(
				Arguments.of("azp", Sets.newLinkedHashSet("aud1", "aud2"), "azp", null),
				Arguments.of("azp", Sets.newLinkedHashSet("aud"), "azp", null),
				Arguments.of("", Sets.newLinkedHashSet("aud1", "aud2"), null, InvalidTokenException.class),
				Arguments.of("", Sets.newLinkedHashSet("aud"), "aud", null),
				Arguments.of("", Sets.newLinkedHashSet(), null, InvalidTokenException.class),
				Arguments.of(null, Sets.newLinkedHashSet("aud"), "aud", null),
				Arguments.of(null, Sets.newLinkedHashSet("aud1", "aud2"), null, InvalidTokenException.class),
				Arguments.of(null, Sets.newLinkedHashSet(), null, InvalidTokenException.class),
				Arguments.of("   ", Sets.newLinkedHashSet("aud"), "aud", null),
				Arguments.of("   ", Sets.newLinkedHashSet("aud1", "aud2"), null, InvalidTokenException.class),
				Arguments.of("   ", Sets.newLinkedHashSet(), null, InvalidTokenException.class));
	}
}