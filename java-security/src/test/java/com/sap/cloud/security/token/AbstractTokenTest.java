package com.sap.cloud.security.token;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.config.Service;

public class AbstractTokenTest {

	private final String jwtString;
	private AbstractToken cut;

	public AbstractTokenTest() throws IOException {
		jwtString = IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		cut = new TestToken(jwtString);
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
	public void getAccessToken() {
		assertThat(cut.getAccessToken()).isEqualTo(jwtString);
	}

	@Test
	public void getBearerAccessToken() {
		assertThat(cut.getBearerAccessToken()).isEqualTo("Bearer " + cut.getAccessToken());
	}

	@Test
	public void getBearerAccessToken_bearerSmallCaps() {
		String bearerSmallCapsJwtstring = "bearer " + jwtString;
		assertThat(new TestToken(bearerSmallCapsJwtstring).getAccessToken()).isEqualTo(jwtString);
	}

	@Test
	public void getBearerAccessToken_bearerLargeCaps() {
		String bearerSmallCapsJwtstring = "Bearer " + jwtString;
		assertThat(new TestToken(bearerSmallCapsJwtstring).getAccessToken()).isEqualTo(jwtString);
	}

	private class TestToken extends AbstractToken {
		public TestToken(String jwtString) {
			super(jwtString);
		}

		@Override
		public Principal getPrincipal() {
			return null;
		}

		@Override
		public Service getService() {
			return null;
		}
	}
}