package com.sap.cloud.security.xsuaa.client;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.isNotNull;

import org.junit.Test;

public class ClientCredentialsTest {
	ClientCredentials cut = new ClientCredentials("clientId", "clientSecret");

	@Test
	public void equals() {
		assertThat(cut.equals(cut), is(true));
		assertThat(cut.equals(new ClientCredentials("clientId", "clientSecret")), is(true));
	}

	@Test
	public void not_equals() {
		assertThat(cut.equals(new ClientCredentials("clientId2", "clientSecret")), is(false));
		assertThat(cut.equals(new ClientCredentials("clientId", "clientSecret2")), is(false));
		assertThat(cut.equals(null), is(false));
		assertThat(cut.equals(new Object()), is(false));
	}

	@Test
	public void hashCoded() {
		int cutHashCode = cut.hashCode();
		assertThat(cutHashCode, is(not(0)));
		assertThat(cutHashCode, is(new ClientCredentials("clientId", "clientSecret").hashCode()));
		assertThat(cutHashCode, is(not(new ClientCredentials("clientId2", "clientSecret").hashCode())));
	}

	@Test
	public void stringify() {
		assertThat(cut.toString(), is("clientId:clientSecret"));
	}
}
