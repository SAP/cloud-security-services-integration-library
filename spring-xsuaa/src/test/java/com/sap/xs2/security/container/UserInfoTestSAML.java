package com.sap.xs2.security.container;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import net.minidev.json.parser.ParseException;

public class UserInfoTestSAML {

	UserInfo token = null;

	@Before
	public void setup() throws Exception {
		token = UserInfoTestUtil.parse("/saml.txt", "java-hello-world");
	}

	@Test
	public void testSAMLToken() throws Exception, ParseException, java.text.ParseException, UserInfoException {

		
		// attributes - old style
		Assert.assertEquals(2, token.getAttribute("cost-center").length);
		Assert.assertEquals("0815", token.getAttribute("cost-center")[0]);
		Assert.assertEquals("4711", token.getAttribute("cost-center")[1]);
		Assert.assertEquals(1, token.getAttribute("country").length);
		Assert.assertEquals("Germany", token.getAttribute("country")[0]);

		// scopes
		Assert.assertEquals(true, token.checkLocalScope("Display"));
		Assert.assertEquals(true, token.checkLocalScope("Create"));
		Assert.assertEquals(true, token.checkLocalScope("Delete"));
		Assert.assertEquals(false, token.checkLocalScope("Other"));
		// client id
		Assert.assertEquals("sb-java-hello-world", token.getClientId());
		// grant type
		Assert.assertEquals("authorization_code", token.getGrantType());

		// logon name
		Assert.assertEquals("Mustermann", token.getLogonName());
		// email
		Assert.assertEquals("max@example.com", token.getEmail());
		// zone
		Assert.assertEquals("11-22-33", token.getIdentityZone());
		Assert.assertEquals("11-22-33", token.getSubaccountId());
		// embedded SAML
		Assert.assertNotNull(token.getHdbToken());
		// ext attr
		Assert.assertEquals("domain\\group1", token.getAdditionalAuthAttribute("external_group"));
		Assert.assertEquals("abcd1234", token.getAdditionalAuthAttribute("external_id"));
		// subdomain
		Assert.assertEquals("testsubdomain", token.getSubdomain());
		// service instance id
		Assert.assertEquals("abcd1234", token.getCloneServiceInstanceId());
		// groups
		Assert.assertEquals(1, token.getSystemAttribute("xs.saml.groups").length);
		Assert.assertEquals("g1", token.getSystemAttribute("xs.saml.groups")[0]);
		// role collections
		Assert.assertEquals(1, token.getSystemAttribute("xs.rolecollections").length);
		Assert.assertEquals("rc1", token.getSystemAttribute("xs.rolecollections")[0]);
	}


}
