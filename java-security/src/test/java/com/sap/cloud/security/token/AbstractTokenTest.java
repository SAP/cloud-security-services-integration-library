package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

public class AbstractTokenTest {

	private final String jwtString;
	private Token cut;

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
	public void getHeaderParameterAsString() {
		assertThat(cut.getHeaderParameterAsString("alg")).isEqualTo("RS256");
	}

	@Test
	public void containsClaim() {
		assertThat(cut.hasClaim("notContained")).isFalse();
		assertThat(cut.hasClaim("grant_type")).isTrue();
	}

	@Test
	public void getClaimAsString() {
		assertThat(cut.getClaimAsString("zid")).isEqualTo("uaa");
	}

	@Test
	public void getClaimAsStringList() {
		assertThat(cut.getClaimAsStringList("aud")).containsExactly("uaa", "sap_osb");
	}

	@Test
	public void getClaimAsStringList_unknownClaim_emptyList() {
		assertThat(cut.getClaimAsStringList("anything")).isEqualTo(Collections.emptyList());
	}

	@Test
	public void getExpiration() {
		assertThat(cut.getExpiration()).isEqualTo(Instant.ofEpochSecond(1572060769L));
	}

	@Test
	public void tokenWithExpirationInTheFuture_isNotExpired() {
		AbstractToken doesNotExpireSoon = new MockTokenBuilder().withExpiration(MockTokenBuilder.NO_EXPIRE_DATE)
				.build();
		when(doesNotExpireSoon.isExpired()).thenCallRealMethod();

		assertThat(doesNotExpireSoon.isExpired()).isFalse();
	}

	@Test
	public void tokenWithExpirationInThePast_isExpired() {
		assertThat(cut.isExpired()).isTrue();
	}

	@Test
	public void tokenWithouthExpirationDate_isNotExpired() {
		AbstractToken neverExpires = new MockTokenBuilder().withExpiration(null).build();
		when(neverExpires.isExpired()).thenCallRealMethod();

		assertThat(neverExpires.isExpired()).isFalse();
	}

	@Test
	public void getNotBefore_notContained_shouldBeNull() {
		assertThat(cut.getNotBefore()).isNull();
	}

	@Test
	public void getTokenValue() {
		assertThat(cut.getTokenValue()).isEqualTo(jwtString);
	}

	@Test
	public void getJsonObject() {
		JsonObject externalAttributes = cut.getClaimAsJsonObject("ext_attr");
		assertThat(externalAttributes.getAsString("enhancer")).isEqualTo("XSUAA");
	}

	@Test
	public void getJsonObject_claimsIsNotAnObject_throwsException() {
		assertThatThrownBy(() -> cut.getClaimAsJsonObject("client_id")).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getJsonObject_claimsDoesNotExist_isNull() {
		assertThat(cut.getClaimAsJsonObject("doesNotExist")).isNull();
	}

}