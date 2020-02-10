package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SapIdTokenTest {

	private SapIdToken cut;

	public SapIdTokenTest() throws IOException {
		cut = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", StandardCharsets.UTF_8));
	}

	@Test
	public void constructor_raiseIllegalArgumentExceptions() {
		assertThatThrownBy(() -> {
			new SapIdToken("");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("jwtToken must not be null / empty");

		assertThatThrownBy(() -> {
			new SapIdToken("abc");
		}).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("JWT token does not consist of 'header'.'payload'.'signature'.");
	}

	@Test
	@Ignore // TODO IAS : principal should return SAP User ID (guid)
	public void getPrincipal() {
		Principal principal = cut.getPrincipal();

		assertThat(principal).isNull();
	}

	@Test
	public void getService() {
		assertThat(cut.getService()).isEqualTo(Service.IAS);
	}

	@Test
	public void getAudiences() {
		assertThat(cut.getAudiences()).isNotEmpty();
		assertThat(cut.getAudiences()).hasSize(1);
		assertThat(cut.getAudiences()).contains("T000310");
	}

}