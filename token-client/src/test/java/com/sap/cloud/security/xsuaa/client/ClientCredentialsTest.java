package com.sap.cloud.security.xsuaa.client;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;

public class ClientCredentialsTest {
	ClientCredentials cut = new ClientCredentials("clientId", "clientSecret");

	@Test
	public void clientCredentials_equals() {
		assertThat(cut.equals(cut), is(true));
		assertThat(cut.equals(new ClientCredentials("clientId", "clientSecret")), is(true));
	}

	@Test
	public void clientCredentials_notequals() {
		assertThat(cut.equals(new ClientCredentials("clientId2", "clientSecret")), is(false));
		assertThat(cut.equals(new ClientCredentials("clientId", "clientSecret2")), is(false));
		assertThat(cut.equals(null), is(false));
		assertThat(cut.equals(new Object()), is(false));
	}
}
