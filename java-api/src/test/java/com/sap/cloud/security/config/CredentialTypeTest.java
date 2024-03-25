/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import org.junit.Assert;
import org.junit.Test;

public class CredentialTypeTest {

	@Test
	public void from() {
		Assert.assertEquals(CredentialType.X509, CredentialType.from("x509"));
		Assert.assertEquals(CredentialType.X509_GENERATED, CredentialType.from("X509_GENERATED"));
		Assert.assertEquals(CredentialType.X509_PROVIDED, CredentialType.from("X509_PROVIDED"));
		Assert.assertEquals(CredentialType.X509_ATTESTED, CredentialType.from("X509_ATTESTED"));
		Assert.assertEquals(CredentialType.INSTANCE_SECRET, CredentialType.from("instance-secret"));
		Assert.assertEquals(CredentialType.BINDING_SECRET, CredentialType.from("binding-secret"));
	}
}