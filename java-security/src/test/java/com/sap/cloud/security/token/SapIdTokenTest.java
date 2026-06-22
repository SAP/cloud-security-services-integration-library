/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import org.junit.jupiter.api.Test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SapIdTokenTest {

	private final SapIdToken cut;
	private final SapIdToken cut2;

	public SapIdTokenTest() throws IOException {
		cut = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", StandardCharsets.UTF_8));
		cut2 = new SapIdToken(IOUtils.resourceToString("/iasTokenWithCnfRSA256.txt", StandardCharsets.UTF_8));
	}

	@Test
	public void constructor_raiseIllegalArgumentExceptions() {
		assertThatThrownBy(() -> new SapIdToken("")).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("jwtToken must not be null / empty");

		assertThatThrownBy(() -> new SapIdToken("abc")).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("JWT token does not consist of 'header'.'payload'.'signature'.");
	}

	@Test
	public void getPrincipal() {
		assertThat(cut.getPrincipal().getName()).isEqualTo("1234567890");
	}

	@Test
	public void getService() {
		assertThat(cut.getService()).isEqualTo(Service.IAS);
	}

	@Test
	public void getAudiences() {
		assertThat(cut.getAudiences()).isNotEmpty();
		assertThat(cut.getAudiences()).hasSize(2);
		assertThat(cut.getAudiences()).contains("T000310");
	}

	@Test
	public void getCnfThumbprint() {
		assertThat(cut.getCnfX509Thumbprint()).isNull();
		assertThat(cut2.getCnfX509Thumbprint()).isEqualTo("fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM");
	}

	@Test
	public void getAppTid() {
		assertThat(cut.getAppTid()).isEqualTo("the-app-tid");
	}

	@Test
	public void getIdType_user() {
		assertThat(tokenWithPayload("{\"sap_id_type\":\"user\"}").getIdType()).isEqualTo(SapIdType.USER);
	}

	@Test
	public void getIdType_app() {
		assertThat(tokenWithPayload("{\"sap_id_type\":\"app\"}").getIdType()).isEqualTo(SapIdType.APP);
	}

	@Test
	public void getIdType_claimMissing_returnsNull() {
		assertThat(cut.getIdType()).isNull();
	}

	@Test
	public void getIdType_unknownClaimValue_returnsNull() {
		assertThat(tokenWithPayload("{\"sap_id_type\":\"future-type\"}").getIdType()).isNull();
	}

	private static SapIdToken tokenWithPayload(String payloadJson) {
		return new SapIdToken(new StubDecodedJwt(payloadJson));
	}

	private static final class StubDecodedJwt implements DecodedJwt {
		private final String payload;

		StubDecodedJwt(String payload) {
			this.payload = payload;
		}

		@Override
		public String getHeader() {
			return "{}";
		}

		@Override
		public String getPayload() {
			return payload;
		}

		@Override
		public String getSignature() {
			return "";
		}

		@Override
		public String getEncodedToken() {
			return "";
		}
	}
}