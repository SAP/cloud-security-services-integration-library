package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.OAuthServerEndpointsProvider;
import com.sap.cloud.security.xsuaa.XsuaaDefaultEndpoints;
import org.junit.Test;

import java.net.URI;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class XsuaaDefaultEndpointsTest {

	@Test
	public void initialize() {
		OAuthServerEndpointsProvider client = new XsuaaDefaultEndpoints(URI.create("http://localhost:8080/uaa"));

		assertThat(client.getAuthorizeEndpoint().toString(), is("http://localhost:8080/uaa/oauth/authorize"));
		assertThat(client.getTokenEndpoint().toString(), is("http://localhost:8080/uaa/oauth/token"));
		assertThat(client.getJwksUri().toString(), is("http://localhost:8080/uaa/token_keys"));
	}

	@Test
	public void initializeWithEndingPathDelimiter() {
		OAuthServerEndpointsProvider client = new XsuaaDefaultEndpoints(URI.create("http://localhost:8080/uaa/"));

		assertThat(client.getAuthorizeEndpoint().toString(), is("http://localhost:8080/uaa/oauth/authorize"));
		assertThat(client.getTokenEndpoint().toString(), is("http://localhost:8080/uaa/oauth/token"));
		assertThat(client.getJwksUri().toString(), is("http://localhost:8080/uaa/token_keys"));
	}
}
