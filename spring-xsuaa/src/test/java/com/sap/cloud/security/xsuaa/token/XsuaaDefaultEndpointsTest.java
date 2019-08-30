package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class XsuaaDefaultEndpointsTest {

	@Test
	public void initialize() {
		OAuth2ServiceEndpointsProvider client = new XsuaaDefaultEndpoints("http://localhost:8080/uaa");

		assertThat(client.getAuthorizeEndpoint().toString(), is("http://localhost:8080/uaa/oauth/authorize"));
		assertThat(client.getTokenEndpoint().toString(), is("http://localhost:8080/uaa/oauth/token"));
		assertThat(client.getJwksUri().toString(), is("http://localhost:8080/uaa/token_keys"));
	}

	@Test
	public void initializeWithEndingPathDelimiter() {
		OAuth2ServiceEndpointsProvider client = new XsuaaDefaultEndpoints("http://localhost:8080/uaa/");

		assertThat(client.getAuthorizeEndpoint().toString(), is("http://localhost:8080/uaa/oauth/authorize"));
		assertThat(client.getTokenEndpoint().toString(), is("http://localhost:8080/uaa/oauth/token"));
		assertThat(client.getJwksUri().toString(), is("http://localhost:8080/uaa/token_keys"));
	}
}
