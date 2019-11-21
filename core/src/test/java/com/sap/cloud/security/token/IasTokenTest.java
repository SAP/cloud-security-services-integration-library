package com.sap.cloud.security.token;

import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class IasTokenTest {

	private IasToken cut;

	public IasTokenTest() throws IOException {
		cut = new IasToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", StandardCharsets.UTF_8));
	}

	@Test
	@Ignore
	// TODO 21.11.19 c5295400: need real token with test data
	public void getPrincipal() throws IOException {
		UserPrincipal principal = cut.getPrincipal();

		assertThat(principal.getLastName()).isEqualTo("lastName");
		assertThat(principal.getFirstName()).isEqualTo("firstName");
		assertThat(principal.getUsername()).isEqualTo("user");
		assertThat(principal.getEmail()).isEqualTo("email");
	}
}