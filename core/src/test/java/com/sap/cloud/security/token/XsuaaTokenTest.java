package com.sap.cloud.security.token;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class XsuaaTokenTest {

	private XsuaaToken clientCredentialsToken;
	private XsuaaToken userToken;

	public XsuaaTokenTest() throws IOException {
		clientCredentialsToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8));
		userToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaUserAccessTokenRSA256.txt", StandardCharsets.UTF_8));
	}

	@Test
	public void getScopes() {
		assertThat(clientCredentialsToken.getScopes()).containsExactly("ROLE_SERVICEBROKER", "uaa.resource");
	}

	@Test
	public void getUserPrincipal() {
		assertThat(userToken.getClaimAsString(TokenClaims.XSUAA.USER_NAME)).isEqualTo("testUser");
		assertThat(userToken.getClaimAsString(TokenClaims.XSUAA.ORIGIN)).isEqualTo("userIdp");
		assertThat(userToken.getPrincipal()).isNotNull();
		assertThat(userToken.getPrincipal().getName()).isEqualTo("user/userIdp/testUser");
	}

	@Test
	public void getClientPrincipal() {
		assertThat(clientCredentialsToken.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo("sap_osb");
		assertThat(clientCredentialsToken.getPrincipal()).isNotNull();
		assertThat(clientCredentialsToken.getPrincipal().getName()).isEqualTo("client/sap_osb");
	}
}