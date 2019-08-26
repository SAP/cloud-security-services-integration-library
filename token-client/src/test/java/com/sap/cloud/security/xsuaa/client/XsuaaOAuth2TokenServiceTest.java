package com.sap.cloud.security.xsuaa.client;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.URI;

import org.junit.Test;
import org.springframework.web.client.RestTemplate;

public class XsuaaOAuth2TokenServiceTest {
	private XsuaaOAuth2TokenService cut = new XsuaaOAuth2TokenService(new RestTemplate());
	private URI tokenEndpointUri = URI.create("https://subdomain.myauth.com/mypath");

	@Test
	public void replaceSubdomain_replacesNothingWhenSubdomainIsNull() {
		URI replacedURI = XsuaaOAuth2TokenService.replaceSubdomain(tokenEndpointUri, null);
		assertThat(replacedURI, is(tokenEndpointUri));
	}

	@Test
	public void replaceSubdomain() {
		URI replacedURI = XsuaaOAuth2TokenService.replaceSubdomain(tokenEndpointUri, "newsubdomain");
		assertThat(replacedURI.toString(), is("https://newsubdomain.myauth.com/mypath"));
	}

	@Test
	public void replaceSubdomain_replacesNothingWhenSubdomainIsEmpty() {
		URI replacedURI = XsuaaOAuth2TokenService.replaceSubdomain(tokenEndpointUri, "");
		assertThat(replacedURI, is(tokenEndpointUri));
	}

	@Test
	public void replaceSubdomain_replacesNothingWhenUrlContainsNoSubdomain() {
		URI replacedURI = XsuaaOAuth2TokenService.replaceSubdomain(URI.create("http://localhost"), "newsubdomain");
		assertThat(replacedURI.toString(), is("http://localhost"));
	}
}
