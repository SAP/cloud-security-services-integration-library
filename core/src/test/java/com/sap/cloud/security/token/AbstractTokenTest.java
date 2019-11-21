package com.sap.cloud.security.token;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

public class AbstractTokenTest {

	private final String jwtString;
	private AbstractToken cut;

	public AbstractTokenTest() throws IOException {
		jwtString = IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		cut = new AbstractToken(jwtString) {
			@Override public Principal getPrincipal() {
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
		assertThat(cut.containsClaim("notContained")).isFalse();
		assertThat(cut.containsClaim("grant_type")).isTrue();
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
	public void getNotBefore_notContained_shouldBeNull() {
		assertThat(cut.getNotBefore()).isNull();
	}

	@Test
	public void getAccessToken() {
		assertThat(cut.getAccessToken()).isEqualTo(jwtString);
	}

}