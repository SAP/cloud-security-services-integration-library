package com.sap.cloud.security.config;

import org.junit.Assert;
import org.junit.Test;

public class CredentialTypeTest {

	@Test
	public void from() {
		Assert.assertEquals(CredentialType.X509, CredentialType.from("x509"));
		Assert.assertEquals(CredentialType.INSTANCE_SECRET, CredentialType.from("instance-secret"));
		Assert.assertEquals(CredentialType.BINDING_SECRET, CredentialType.from("binding-secret"));
	}
}