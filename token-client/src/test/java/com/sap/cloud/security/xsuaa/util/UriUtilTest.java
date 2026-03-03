/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import java.net.URI;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

public class UriUtilTest {

	private final URI tokenEndpointUri = URI.create("https://subdomain.myauth.com/mypath");

	@Test
	public void replaceSubdomain_replacesNothingWhenSubdomainIsNull() {
		URI replacedURI = UriUtil.replaceSubdomain(tokenEndpointUri, null);
		assertThat(replacedURI).isEqualTo(tokenEndpointUri);
	}

	@Test
	public void replaceSubdomain() {
		URI replacedURI = UriUtil.replaceSubdomain(tokenEndpointUri, "newsubdomain");
		assertThat(replacedURI.toString()).isEqualTo("https://newsubdomain.myauth.com/mypath");
	}

	@Test
	public void replaceSubdomain_replacesNothingWhenSubdomainIsEmpty() {
		URI replacedURI = UriUtil.replaceSubdomain(tokenEndpointUri, "");
		assertThat(replacedURI).isEqualTo(tokenEndpointUri);
	}

	@Test
	public void replaceSubdomain_replacesNothingWhenUrlContainsNoSubdomain() {
		URI replacedURI = UriUtil.replaceSubdomain(URI.create("http://localhost"), "newsubdomain");
		assertThat(replacedURI.toString()).isEqualTo("http://localhost");
	}

	@Test
	public void replaceSubdomain_noUrlSchemaGiven() {
		URI replacedURI = UriUtil.replaceSubdomain(URI.create("localhost"), "newsubdomain");
		assertThat(replacedURI.toString()).isEqualTo("localhost");
	}
}
