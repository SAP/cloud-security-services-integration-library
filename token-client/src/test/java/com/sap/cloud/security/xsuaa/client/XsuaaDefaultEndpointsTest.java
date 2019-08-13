package com.sap.cloud.security.xsuaa.client;

import org.junit.Test;

import java.net.URI;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

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

	@Test
	public void replaceSubdomain_replacesNothingWhenSubdomainIsNull() {
		URI replacedURI = XsuaaDefaultEndpoints.replaceSubdomain(cut.getTokenEndpoint(), null);
		assertThat(replacedURI, is(cut.getTokenEndpoint()));
	}

	@Test
	public void replaceSubdomain() {
		URI replacedURI = XsuaaDefaultEndpoints.replaceSubdomain(cut.getTokenEndpoint(), "newsubdomain");
		assertThat(replacedURI.toString(), is("https://newsubdomain.myauth.com/oauth/token"));
	}

	@Test
	public void replaceSubdomain_replacesNothingWhenSubdomainIsEmpty() {
		URI replacedURI = XsuaaDefaultEndpoints.replaceSubdomain(cut.getTokenEndpoint(), "");
		assertThat(replacedURI, is(cut.getTokenEndpoint()));
	}

	@Test
	public void replaceSubdomain_replacesNothingWhenUrlContainsNoSubdomain() {
		URI replacedURI = XsuaaDefaultEndpoints.replaceSubdomain(URI.create("http://localhost"), "newsubdomain");
		assertThat(replacedURI.toString(), is("http://localhost"));
	}
}
