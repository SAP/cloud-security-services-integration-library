/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.CredentialType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class XsuaaServiceConfigurationCustomTest {
	XsuaaCredentials credentials = new XsuaaCredentials();
	XsuaaServiceConfigurationCustom cut;

	@BeforeEach
	public void setup() {
		credentials.setClientId("cid");
		credentials.setClientSecret("secret");
		credentials.setTenantId("tenant-id");
		credentials.setSubaccountId("subaccount-id");
		credentials.setUaaDomain("uaaDomain");
		credentials.setApiUrl("apiUrl");
		credentials.setUrl("url");
		credentials.setXsAppName("xsappname");
		credentials.setCertificate("-----BEGIN CERTIFICATE-----");
		credentials.setCertUrl("cert-url");
		credentials.setPrivateKey("-----BEGIN RSA PRIVATE KEY-----");
		credentials.setCredentialType(CredentialType.X509);

		cut = new XsuaaServiceConfigurationCustom(credentials);
	}

	@Test
	void getterShouldReturnValuesFromCredentials() {
		assertEquals(credentials.getClientId(), cut.getClientId());
		assertEquals(credentials.getClientSecret(), cut.getClientSecret());
		assertEquals(credentials.getTenantId(), cut.getTenantId());
		assertEquals(credentials.getSubaccountId(), cut.getSubaccountId());
		assertEquals(credentials.getUaaDomain(), cut.getUaaDomain());
		assertEquals(credentials.getApiUrl(), cut.getApiUrl());
		assertEquals(credentials.getUrl(), cut.getUaaUrl());
		assertEquals(credentials.getXsAppName(), cut.getAppId());
		assertEquals(credentials.getCredentialType(), cut.getCredentialType());
		assertEquals(credentials.getCertUrl(), cut.getCertUrl().toString());
		assertEquals(credentials.getCertificate(), cut.getClientIdentity().getCertificate());
		assertEquals(credentials.getPrivateKey(), cut.getClientIdentity().getKey());
	}

	@Test
	void resolveClientIdentityType() {
		assertTrue(cut.getClientIdentity().isCertificateBased());
		assertTrue(cut.getClientIdentity().isValid());
	}

	@Test
	void getVerificationKeyIsNull() {
		assertNull(cut.getVerificationKey());
	}
}
