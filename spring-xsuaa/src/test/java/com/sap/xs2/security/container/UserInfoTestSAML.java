package com.sap.xs2.security.container;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import net.minidev.json.parser.ParseException;

public class UserInfoTestSAML {

	UserInfo samlUserInfo = null;

	@Before
	public void setup() throws Exception {
		samlUserInfo = UserInfoTestUtil.createFromTemplate("/saml.txt", "java-hello-world");
	}

	@Test
	public void testSAMLToken() throws Exception {
		// attributes - old style
		Assert.assertEquals(2, samlUserInfo.getAttribute("cost-center").length);
		Assert.assertEquals("0815", samlUserInfo.getAttribute("cost-center")[0]);
		Assert.assertEquals("4711", samlUserInfo.getAttribute("cost-center")[1]);
		Assert.assertEquals(1, samlUserInfo.getAttribute("country").length);
		Assert.assertEquals("Germany", samlUserInfo.getAttribute("country")[0]);

		// scopes
		Assert.assertEquals(true, samlUserInfo.checkLocalScope("Display"));
		Assert.assertEquals(true, samlUserInfo.checkLocalScope("Create"));
		Assert.assertEquals(true, samlUserInfo.checkLocalScope("Delete"));
		Assert.assertEquals(false, samlUserInfo.checkLocalScope("Other"));
		// client id
		Assert.assertEquals("sb-java-hello-world", samlUserInfo.getClientId());
		// grant type
		Assert.assertEquals("authorization_code", samlUserInfo.getGrantType());

		// logon name
		Assert.assertEquals("Mustermann", samlUserInfo.getLogonName());
		// email
		Assert.assertEquals("max@example.com", samlUserInfo.getEmail());
		// zone
		Assert.assertEquals("11-22-33", samlUserInfo.getIdentityZone());
		Assert.assertEquals("11-22-33", samlUserInfo.getSubaccountId());
		// embedded SAML
		Assert.assertNotNull(samlUserInfo.getHdbToken());
		// ext attr
		Assert.assertEquals("domain\\group1", samlUserInfo.getAdditionalAuthAttribute("external_group"));
		Assert.assertEquals("abcd1234", samlUserInfo.getAdditionalAuthAttribute("external_id"));
		// subdomain
		Assert.assertEquals("testsubdomain", samlUserInfo.getSubdomain());
		// service instance id
		Assert.assertEquals("abcd1234", samlUserInfo.getCloneServiceInstanceId());
		// groups
		Assert.assertEquals(1, samlUserInfo.getSystemAttribute("xs.saml.groups").length);
		Assert.assertEquals("g1", samlUserInfo.getSystemAttribute("xs.saml.groups")[0]);
		// role collections
		Assert.assertEquals(1, samlUserInfo.getSystemAttribute("xs.rolecollections").length);
		Assert.assertEquals("rc1", samlUserInfo.getSystemAttribute("xs.rolecollections")[0]);
	}
}
