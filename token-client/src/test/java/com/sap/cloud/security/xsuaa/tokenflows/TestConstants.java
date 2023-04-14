/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.ClientCredentials;

import java.net.URI;

//@formatter:off
interface TestConstants {
	URI XSUAA_BASE_URI = URI.create("https://subdomain.authentication.eu10.hana.ondemand.com/");
	URI TOKEN_ENDPOINT_URI = URI.create("https://subdomain.authentication.eu10.hana.ondemand.com/oauth/token");
	ClientCredentials CLIENT_CREDENTIALS = new ClientCredentials("sb-spring-netflix-demo!t12291",
			"2Tc2Xz7DNy4KiACwvunulmxF32w=");
	String USERNAME = "Bob";
	String PASSWORD = "qwerty";
	String ACCESS_TOKEN = "8fea5fdea005417d8c7104a5a4165da2";
	String REFRESH_TOKEN = "c9336d3de6b7450b8b14cc61362d595d";
	long EXPIRED_IN = 4223;
}
//@formatter:on