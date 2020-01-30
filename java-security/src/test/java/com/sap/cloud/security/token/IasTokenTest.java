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

public class IasTokenTest {

	private IasToken cut;

	public IasTokenTest() throws IOException {
		cut = new IasToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", StandardCharsets.UTF_8));
	}

	@Test
	public void constructor_raiseIllegalArgumentExceptions() {
		assertThatThrownBy(() -> {
			new IasToken("");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("accessToken must not be null / empty");

		assertThatThrownBy(() -> {
			new IasToken("abc");
		}).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("JWT token does not consist of 'header'.'payload'.'signature'.");
	}

	@Test
	@Ignore
	// TODO IAS: need real token with test data
	public void getPrincipal() {
		Principal principal = cut.getPrincipal();

		assertThat(principal).isNotNull();
		assertThat(principal.getName()).isEqualTo("TODO");
	}

	@Test
	public void getGrantType() {
		assertThat(cut.getGrantType()).isEqualTo(GrantType.JWT_BEARER);
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