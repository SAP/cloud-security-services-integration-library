package com.sap.cloud.security.token;

import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class XsuaaTokenTest {

	private XsuaaToken cut;

	public XsuaaTokenTest() throws IOException {
		cut = new XsuaaToken(IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8));
	}

	@Test
	public void getScopes() throws IOException {
		assertThat(cut.getScopes()).containsExactly("ROLE_SERVICEBROKER", "uaa.resource");
	}

	@Test
	@Ignore
	// TODO 21.11.19 c5295400: need real token with test data
	public void getPrincipal() {
		UserPrincipal principal = cut.getPrincipal();

		assertThat(principal).isNotNull();
		assertThat(principal.getEmail()).isEqualTo("email");
		assertThat(principal.getFirstName()).isEqualTo("firstName");
		assertThat(principal.getLastName()).isEqualTo("lastName");
		assertThat(principal.getUsername()).isEqualTo("userName");

	}
}