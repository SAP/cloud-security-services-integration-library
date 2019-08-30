package com.sap.cloud.security.xsuaa.client;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;

public class XsuaaDefaultEndpointsTest {
	XsuaaDefaultEndpoints cut = new XsuaaDefaultEndpoints("https://subdomain.myauth.com");

	@Test
	public void getTokenEndpoint() {
		assertThat(cut.getTokenEndpoint().toString(), is("https://subdomain.myauth.com/oauth/token"));
	}

	@Test
	public void getAuthorizeEndpoint() {
		assertThat(cut.getAuthorizeEndpoint().toString(), is("https://subdomain.myauth.com/oauth/authorize"));
	}

	@Test
	public void getJwksUri() {
		assertThat(cut.getJwksUri().toString(), is("https://subdomain.myauth.com/token_keys"));
	}

}
