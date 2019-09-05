package com.sap.cloud.security.xsuaa.client;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;

public class XsuaaDefaultEndpointsTest {

	@Test
	public void getTokenEndpoint() {
		OAuth2ServiceEndpointsProvider cut = createXsuaaDefaultEndpointProvider("https://subdomain.myauth.com");

		assertThat(cut.getTokenEndpoint().toString(), is("https://subdomain.myauth.com/oauth/token"));
	}

	@Test
	public void getAuthorizeEndpoint() {
		OAuth2ServiceEndpointsProvider cut = createXsuaaDefaultEndpointProvider("https://subdomain.myauth.com");

		assertThat(cut.getAuthorizeEndpoint().toString(), is("https://subdomain.myauth.com/oauth/authorize"));
	}

	@Test
	public void getJwksUri() {
		OAuth2ServiceEndpointsProvider cut = createXsuaaDefaultEndpointProvider("https://subdomain.myauth.com");

		assertThat(cut.getJwksUri().toString(), is("https://subdomain.myauth.com/token_keys"));
	}

	@Test
	public void withEndingPathDelimiter() {
		OAuth2ServiceEndpointsProvider cut = createXsuaaDefaultEndpointProvider("http://localhost:8080/uaa/");

		assertThat(cut.getAuthorizeEndpoint().toString(), is("http://localhost:8080/uaa/oauth/authorize"));
		assertThat(cut.getTokenEndpoint().toString(), is("http://localhost:8080/uaa/oauth/token"));
		assertThat(cut.getJwksUri().toString(), is("http://localhost:8080/uaa/token_keys"));
	}

	@Test
	public void withQueryParameters() {
		OAuth2ServiceEndpointsProvider cut = createXsuaaDefaultEndpointProvider("http://localhost:8080/uaa?abc=123");

		assertThat(cut.getAuthorizeEndpoint().toString(), is("http://localhost:8080/uaa/oauth/authorize?abc=123"));
		assertThat(cut.getTokenEndpoint().toString(), is("http://localhost:8080/uaa/oauth/token?abc=123"));
		assertThat(cut.getJwksUri().toString(), is("http://localhost:8080/uaa/token_keys?abc=123"));
	}

	@Test
	public void withQueryParametersAndEndingPathDelimiter() {
		OAuth2ServiceEndpointsProvider cut = createXsuaaDefaultEndpointProvider(
				"http://localhost:8080/uaa/?abc=123");

		assertThat(cut.getAuthorizeEndpoint().toString(), is("http://localhost:8080/uaa/oauth/authorize?abc=123"));
		assertThat(cut.getTokenEndpoint().toString(), is("http://localhost:8080/uaa/oauth/token?abc=123"));
		assertThat(cut.getJwksUri().toString(), is("http://localhost:8080/uaa/token_keys?abc=123"));
	}

	private OAuth2ServiceEndpointsProvider createXsuaaDefaultEndpointProvider(String baseUri) {
		return new XsuaaDefaultEndpoints(baseUri);
	}
}
