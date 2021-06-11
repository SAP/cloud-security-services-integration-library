/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.CredentialType;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.net.URI;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class XsuaaDefaultEndpointsTest {

	private static OAuth2ServiceConfiguration oAuth2ServiceConfiguration;
	private static final String URL = "https://subdomain.myauth.com";
	private static final String CERT_URL = "https://subdomain.cert.myauth.com";

	@Before
	public void setUp() {
		oAuth2ServiceConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		Mockito.when(oAuth2ServiceConfiguration.getUrl()).thenReturn(URI.create(URL));
	}

	@Test
	public void getTokenEndpoint() {
		OAuth2ServiceEndpointsProvider cut = createXsuaaDefaultEndpointProvider(URL);

		assertThat(cut.getTokenEndpoint().toString(), is(URL + "/oauth/token"));

		Mockito.when(oAuth2ServiceConfiguration.getCredentialType()).thenReturn(CredentialType.INSTANCE_SECRET);
		OAuth2ServiceEndpointsProvider cut2 = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);

		assertThat(cut2.getTokenEndpoint().toString(), is(URL + "/oauth/token"));
	}

	@Test
	public void getTokenEndpointX509() {
		Mockito.when(oAuth2ServiceConfiguration.getCertUrl()).thenReturn(URI.create(CERT_URL));
		Mockito.when(oAuth2ServiceConfiguration.getCredentialType()).thenReturn(CredentialType.X509);
		OAuth2ServiceEndpointsProvider cut = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);
		assertThat(cut.getTokenEndpoint().toString(), is(CERT_URL + "/oauth/token"));
	}

	@Test
	public void getAuthorizeEndpoint() {
		OAuth2ServiceEndpointsProvider cut = createXsuaaDefaultEndpointProvider(URL);

		assertThat(cut.getAuthorizeEndpoint().toString(), is(URL + "/oauth/authorize"));

		Mockito.when(oAuth2ServiceConfiguration.getCredentialType()).thenReturn(CredentialType.INSTANCE_SECRET);
		OAuth2ServiceEndpointsProvider cut2 = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);

		assertThat(cut2.getAuthorizeEndpoint().toString(), is(URL + "/oauth/authorize"));
	}

	@Test
	public void getAuthorizeEndpointX509() {
		Mockito.when(oAuth2ServiceConfiguration.getCertUrl()).thenReturn(URI.create(CERT_URL));
		Mockito.when(oAuth2ServiceConfiguration.getCredentialType()).thenReturn(CredentialType.X509);
		OAuth2ServiceEndpointsProvider cut2 = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);

		assertThat(cut2.getAuthorizeEndpoint().toString(), is(CERT_URL + "/oauth/authorize"));
	}

	@Test
	public void getJwksUri() {
		OAuth2ServiceEndpointsProvider cut = createXsuaaDefaultEndpointProvider(URL);

		assertThat(cut.getJwksUri().toString(), is(URL + "/token_keys"));
	}

	@Test
	public void getJwksUriX509() {
		Mockito.when(oAuth2ServiceConfiguration.getCertUrl()).thenReturn(URI.create(CERT_URL));
		Mockito.when(oAuth2ServiceConfiguration.getCredentialType()).thenReturn(CredentialType.X509);
		OAuth2ServiceEndpointsProvider cut2 = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);

		assertThat(cut2.getJwksUri().toString(), is(CERT_URL + "/token_keys"));
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
