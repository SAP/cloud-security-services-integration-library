package com.sap.cloud.security.token;

import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;

public class IasTokenTest {

	private IasToken cut;

	public IasTokenTest() throws IOException {
		cut = new IasToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", StandardCharsets.UTF_8));
	}

	@Test
	@Ignore
	public void getPrincipal() {
		Principal principal = cut.getPrincipal();

		assertThat(principal).isNotNull();
		assertThat(principal.getName()).isEqualTo("TODO");
	}
}