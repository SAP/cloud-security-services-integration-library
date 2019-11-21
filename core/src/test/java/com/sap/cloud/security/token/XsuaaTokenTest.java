package com.sap.cloud.security.token;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class XsuaaTokenTest {

	@Test
	public void getScopes() throws IOException {
		String jwtString = IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		XsuaaToken cut = new XsuaaToken(jwtString);

		assertThat(cut.getScopes()).containsExactly("ROLE_SERVICEBROKER", "uaa.resource");
	}

}