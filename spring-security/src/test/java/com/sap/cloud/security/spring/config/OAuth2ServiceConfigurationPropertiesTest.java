/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.config.CredentialType;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFConstants.*;
import org.junit.jupiter.api.Test;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static org.junit.jupiter.api.Assertions.*;

class OAuth2ServiceConfigurationPropertiesTest {
	OAuth2ServiceConfigurationProperties cutIas = new OAuth2ServiceConfigurationProperties(Service.IAS);
	OAuth2ServiceConfigurationProperties cutXsuaa = new OAuth2ServiceConfigurationProperties(Service.XSUAA);
	private static final String ANY_VALUE = "anyValue";

	@Test
	void setGetClientId() {
		cutIas.setClientId(ANY_VALUE);
		assertEquals(ANY_VALUE, cutIas.getClientId());
		assertTrue(cutIas.hasProperty(CFConstants.CLIENT_ID));
		assertEquals(ANY_VALUE, cutIas.getProperty(CFConstants.CLIENT_ID));

		cutXsuaa.setClientId(ANY_VALUE);
		assertEquals(ANY_VALUE, cutXsuaa.getClientId());
		assertTrue(cutXsuaa.hasProperty(CFConstants.CLIENT_ID));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(CFConstants.CLIENT_ID));
	}

	@Test
	void setGetClientSecret() {
		cutIas.setClientSecret(ANY_VALUE);
		assertEquals(ANY_VALUE, cutIas.getClientSecret());
		assertTrue(cutIas.hasProperty(CLIENT_SECRET));
		assertEquals(ANY_VALUE, cutIas.getProperty(CLIENT_SECRET));

		cutXsuaa.setClientSecret(ANY_VALUE);
		assertEquals(ANY_VALUE, cutXsuaa.getClientSecret());
		assertTrue(cutXsuaa.hasProperty(CLIENT_SECRET));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(CLIENT_SECRET));
	}

	@Test
	void setGetCertificateAndKeyIAS() {
		cutIas.setKey(ANY_VALUE);
		cutIas.setCertificate(ANY_VALUE);
		cutIas.setClientId(ANY_VALUE);
		cutIas.setClientSecret(ANY_VALUE); // to make sure that getClientIdentity uses ClientCertificate impl as default
											// when possible
		assertEquals(ANY_VALUE, cutIas.getClientIdentity().getKey());
		assertEquals(ANY_VALUE, cutIas.getClientIdentity().getCertificate());
		assertTrue(cutIas.getClientIdentity().isCertificateBased());
		assertTrue(cutIas.hasProperty(KEY));
		assertTrue(cutIas.hasProperty(CERTIFICATE));
		assertEquals(ANY_VALUE, cutIas.getProperty(CLIENT_SECRET));
		assertEquals(ANY_VALUE, cutIas.getProperty(KEY));
		assertEquals(ANY_VALUE, cutIas.getProperty(CERTIFICATE));
	}

	@Test
	void setGetCertificateAndKeyXSUAA() {
		cutXsuaa.setCertificate(ANY_VALUE);
		cutXsuaa.setKey(ANY_VALUE);
		cutXsuaa.setClientId(ANY_VALUE);
		cutXsuaa.setClientSecret(ANY_VALUE); // to make sure that getClientIdentity uses ClientCertificate impl as
												// default when possible
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(CLIENT_SECRET));
		assertEquals(ANY_VALUE, cutXsuaa.getClientIdentity().getCertificate());
		assertEquals(ANY_VALUE, cutXsuaa.getClientIdentity().getKey());
		assertTrue(cutXsuaa.hasProperty(CERTIFICATE));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(CERTIFICATE));
		assertTrue(cutXsuaa.hasProperty(KEY));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(KEY));
		assertTrue(cutXsuaa.getClientIdentity().isCertificateBased());
	}

	@Test
	void getClientIdentityResolvesToClientCredentials() {
		cutIas.setClientId(ANY_VALUE);
		cutIas.setClientSecret(ANY_VALUE);
		assertFalse(cutIas.getClientIdentity().isCertificateBased());

		cutXsuaa.setClientId(ANY_VALUE);
		cutXsuaa.setClientSecret(ANY_VALUE);
		assertFalse(cutXsuaa.getClientIdentity().isCertificateBased());
	}

	@Test
	void setGetCredentialType() {
		cutXsuaa.setCertificate(ANY_VALUE);
		cutXsuaa.setKey(ANY_VALUE);
		cutXsuaa.setClientId(ANY_VALUE);
		cutXsuaa.setCredentialType("x509");
		assertEquals(CredentialType.X509, cutXsuaa.getCredentialType());
		assertTrue(cutXsuaa.hasProperty(XSUAA.CREDENTIAL_TYPE));
		assertEquals("x509", cutXsuaa.getProperty(XSUAA.CREDENTIAL_TYPE));

		assertNull(cutIas.getCredentialType());
		assertFalse(cutIas.getClientIdentity().isCertificateBased());
		cutIas.setCertificate(ANY_VALUE);
		cutIas.setKey(ANY_VALUE);
		cutIas.setClientId(ANY_VALUE);
		assertTrue(cutIas.getClientIdentity().isCertificateBased());
		assertEquals(CredentialType.X509, cutIas.getCredentialType());
	}

	@Test
	void setGetUrl() {
		cutIas.setUrl(ANY_VALUE);
		assertEquals(ANY_VALUE, cutIas.getUrl().toString());
		assertTrue(cutIas.hasProperty(URL));
		assertEquals(ANY_VALUE, cutIas.getProperty(URL));

		cutXsuaa.setUrl(ANY_VALUE);
		assertEquals(ANY_VALUE, cutXsuaa.getUrl().toString());
		assertTrue(cutXsuaa.hasProperty(URL));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(URL));
	}

	@Test
	void setGetCertUrl() {
		cutXsuaa.setCertUrl(ANY_VALUE);
		assertEquals(ANY_VALUE, cutXsuaa.getCertUrl().toString());
		assertTrue(cutXsuaa.hasProperty(XSUAA.CERT_URL));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(XSUAA.CERT_URL));
	}

	@Test
	void getProperties() {
		cutIas.setClientId(ANY_VALUE);
		cutIas.setClientSecret(ANY_VALUE);
		assertEquals(ANY_VALUE, cutIas.getProperties().get(CLIENT_ID));
		assertEquals(ANY_VALUE, cutIas.getProperties().get(CLIENT_SECRET));
		assertNull(cutIas.getProperties().get(URL));
	}

	@Test
	void setGetService() {
		assertEquals(Service.IAS, cutIas.getService());
		assertEquals(Service.XSUAA, cutXsuaa.getService());
	}

	@Test
	void setGetUaaDomain() {
		cutXsuaa.setUaaDomain(ANY_VALUE);
		assertTrue(cutXsuaa.hasProperty(XSUAA.UAA_DOMAIN));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(XSUAA.UAA_DOMAIN));
	}

	@Test
	void setGetXsAppName() {
		cutXsuaa.setXsAppName(ANY_VALUE);
		assertTrue(cutXsuaa.hasProperty(XSUAA.APP_ID));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(XSUAA.APP_ID));
	}

	@Test
	void setGetVerificationKey() {
		cutXsuaa.setVerificationKey(ANY_VALUE);
		assertTrue(cutXsuaa.hasProperty(XSUAA.VERIFICATION_KEY));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(XSUAA.VERIFICATION_KEY));
	}

	@Test
	void isLegacyMode() {
		assertFalse(cutXsuaa.isLegacyMode());
	}

	@Test
	void setGetConfiguration() {
		assertEquals(cutIas.getConfiguration(), cutIas.getConfiguration());
		assertNotEquals(cutIas.getConfiguration(), cutXsuaa.getConfiguration());
	}
}