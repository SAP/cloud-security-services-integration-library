/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.junit.jupiter.api.Test;

import java.net.URI;
import org.junit.jupiter.api.Test;

import static com.sap.cloud.security.config.CredentialType.INSTANCE_SECRET;
import org.junit.jupiter.api.Test;
import static com.sap.cloud.security.config.CredentialType.X509;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;

public class XsuaaDefaultEndpointsTest {

	private static OAuth2ServiceConfiguration oAuth2ServiceConfiguration;
	private static final String URL = "https://subdomain.myauth.com";
	private static final String CERT_URL = "https://subdomain.cert.myauth.com";
	private OAuth2ServiceEndpointsProvider cut;

	@BeforeEach
	public void setUp() {
		oAuth2ServiceConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
	}

	@Test
	public void getEndpoints() {
		Mockito.when(oAuth2ServiceConfiguration.getUrl()).thenReturn(URI.create(URL));
		Mockito.when(oAuth2ServiceConfiguration.getCredentialType()).thenReturn(INSTANCE_SECRET);

		cut = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);

		assertThat(cut.getTokenEndpoint().toString()).isEqualTo(URL + "/oauth/token");
		assertThat(cut.getAuthorizeEndpoint().toString()).isEqualTo(URL + "/oauth/authorize");
		assertThat(cut.getJwksUri().toString()).isEqualTo(URL + "/token_keys");
	}

	@Test
	public void getEndpoints_forX509OAuth2ServiceConfiguration() {
		Mockito.when(oAuth2ServiceConfiguration.getUrl()).thenReturn(URI.create(URL));
		Mockito.when(oAuth2ServiceConfiguration.getCertUrl()).thenReturn(URI.create(CERT_URL));
		Mockito.when(oAuth2ServiceConfiguration.getCredentialType()).thenReturn(X509);

		cut = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);

		assertThat(cut.getTokenEndpoint().toString()).isEqualTo(CERT_URL + "/oauth/token");
		assertThat(cut.getAuthorizeEndpoint().toString()).isEqualTo(CERT_URL + "/oauth/authorize");
		assertThat(cut.getJwksUri().toString()).isEqualTo(URL + "/token_keys");
	}

	@Test
	public void getEndpoint_forCertUrl() {
		cut = new XsuaaDefaultEndpoints(URL, CERT_URL);

		assertThat(cut.getTokenEndpoint().toString()).isEqualTo(CERT_URL + "/oauth/token");
	}

	@Test
	public void getEndpoint_throwsException_whenBaseUriIsNull() {
		assertThatThrownBy(() -> new XsuaaDefaultEndpoints(null, CERT_URL))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void getJwksUri_throwsException_whenBaseUriIsNull() {
		Mockito.when(oAuth2ServiceConfiguration.getCertUrl()).thenReturn(URI.create(CERT_URL));
		Mockito.when(oAuth2ServiceConfiguration.getCredentialType()).thenReturn(X509);

		cut = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);

		assertThat(cut.getTokenEndpoint().toString()).isEqualTo(CERT_URL + "/oauth/token"); // ok
		assertThatThrownBy(() -> cut.getJwksUri())
				.isInstanceOf(IllegalArgumentException.class); // raise exception
	}

	@Test
	public void withEndingPathDelimiter() {
		cut = createXsuaaDefaultEndpointProvider("http://localhost:8080/uaa/");

		assertThat(cut.getAuthorizeEndpoint().toString()).isEqualTo("http://localhost:8080/uaa/oauth/authorize");
		assertThat(cut.getTokenEndpoint().toString()).isEqualTo("http://localhost:8080/uaa/oauth/token");
		assertThat(cut.getJwksUri().toString()).isEqualTo("http://localhost:8080/uaa/token_keys");
	}

	@Test
	public void withQueryParameters() {
		cut = createXsuaaDefaultEndpointProvider("http://localhost:8080/uaa?abc=123");

		assertThat(cut.getAuthorizeEndpoint().toString()).isEqualTo("http://localhost:8080/uaa/oauth/authorize?abc=123");
		assertThat(cut.getTokenEndpoint().toString()).isEqualTo("http://localhost:8080/uaa/oauth/token?abc=123");
		assertThat(cut.getJwksUri().toString()).isEqualTo("http://localhost:8080/uaa/token_keys?abc=123");
	}

	@Test
	public void withQueryParametersAndEndingPathDelimiter() {
		cut = createXsuaaDefaultEndpointProvider(
				"http://localhost:8080/uaa/?abc=123");

		assertThat(cut.getAuthorizeEndpoint().toString()).isEqualTo("http://localhost:8080/uaa/oauth/authorize?abc=123");
		assertThat(cut.getTokenEndpoint().toString()).isEqualTo("http://localhost:8080/uaa/oauth/token?abc=123");
		assertThat(cut.getJwksUri().toString()).isEqualTo("http://localhost:8080/uaa/token_keys?abc=123");
	}

	private OAuth2ServiceEndpointsProvider createXsuaaDefaultEndpointProvider(String baseUri) {
		return new XsuaaDefaultEndpoints(baseUri, null);
	}
}
