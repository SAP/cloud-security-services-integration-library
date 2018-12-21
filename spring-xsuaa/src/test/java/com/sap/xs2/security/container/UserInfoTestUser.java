package com.sap.xs2.security.container;

import java.util.Calendar;
import java.util.TimeZone;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import com.sap.xsa.security.container.XSUserInfoException;

import net.minidev.json.parser.ParseException;

public class UserInfoTestUser {

	private UserInfo infoUser = null;
	private UserInfo infoUserNoAttr = null;
	
	@Before
	public void setup() throws Exception {
		infoUser = UserInfoTestUtil.createFromJwtFile("/token_user.txt", "java-hello-world");
		infoUserNoAttr = UserInfoTestUtil.createFromJwtFile("/token_user_noattr.txt", "java-hello-world");
	}

	@Test
	public void testSAMLToken() throws Exception {

		UserInfo token = UserInfoTestUtil.createFromTemplate("/saml.txt", "java-hello-world");
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

	@Test
	public void getLogonName() throws XSUserInfoException {
		Assert.assertEquals("WOLFGANG", infoUser.getLogonName());
	}

	@Test
	public void getEmail() throws XSUserInfoException {
		Assert.assertEquals("WOLFGANG@unknown", infoUser.getEmail());
	}

	@Test(expected = UserInfoException.class)
	public void getGivenName() throws XSUserInfoException {
		infoUser.getGivenName(); // not in samlUserInfo
	}

	@Test(expected = UserInfoException.class)
	public void getFamilyName() throws XSUserInfoException {
		infoUser.getFamilyName(); // not in samlUserInfo
	}

	@Test
	public void getOrigin() throws XSUserInfoException {
		Assert.assertEquals("useridp", infoUser.getOrigin());
	}

	@Ignore
	@Test
	public void getJwtAlg() throws XSUserInfoException {
		// Assert.assertEquals(1, infoUser.getJwtAlgId());
	}

	@Test
	public void getIdentityZone() throws UserInfoException {
		Assert.assertEquals("uaa", infoUser.getIdentityZone());
		Assert.assertEquals("uaa", infoUser.getSubaccountId());
	}

	@Test
	public void getClientId() throws UserInfoException {
		Assert.assertEquals("sb-java-hello-world", infoUser.getClientId());
	}

	@Test
	public void getExpirationDate() throws UserInfoException {
		// Expected date: Tue Sep 22 22:55:22 CEST 2015
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(infoUser.getExpirationDate());
		calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
		Assert.assertEquals("Year", 2015, calendar.get(Calendar.YEAR));
		Assert.assertEquals("Month", Calendar.SEPTEMBER, calendar.get(Calendar.MONTH));
		Assert.assertEquals("Day", 22, calendar.get(Calendar.DAY_OF_MONTH));
		Assert.assertEquals("Hours", 20, calendar.get(Calendar.HOUR_OF_DAY));
		Assert.assertEquals("Minutes", 55, calendar.get(Calendar.MINUTE));
		Assert.assertEquals("Seconds", 22, calendar.get(Calendar.SECOND));
	}

	@Test
	public void checkScope() throws UserInfoException {
		Assert.assertEquals(false, infoUser.checkScope("cloud_controller.read"));
		Assert.assertEquals(true, infoUser.checkScope("java-hello-world.Display"));
	}

	@Test
	public void checkLocalScopeXsappname() throws UserInfoException {
		infoUser.setXSAppname("cloud_controller");
		Assert.assertEquals(false, infoUser.checkLocalScope("read"));
		infoUser.setXSAppname("java-hello-world");
		Assert.assertEquals(true, infoUser.checkLocalScope("Display"));
	}

	@Test
	public void getAttribute() throws XSUserInfoException {
		String[] cost_center = infoUser.getAttribute("cost center");
		Assert.assertEquals(2, cost_center.length);
		Assert.assertEquals("0815", cost_center[0]);
		Assert.assertEquals("4711", cost_center[1]);
		String[] country = infoUser.getAttribute("country");
		Assert.assertEquals(1, country.length);
		Assert.assertEquals("Germany", country[0]);
	}

	@Test
	public void testServiceInstanceId() throws XSUserInfoException {
		Assert.assertEquals("abcd1234", infoUser.getCloneServiceInstanceId());
	}

	@Test
	public void testAdditionalAuthAttr() throws XSUserInfoException {
		Assert.assertEquals("abcd1234", infoUser.getAdditionalAuthAttribute("external_id"));
	}

	@Test
	public void getToken() throws XSUserInfoException {
		Assert.assertNotNull("Token must not be null", infoUser.getHdbToken());
		Assert.assertTrue(!infoUser.getHdbToken().isEmpty());
		Assert.assertTrue(infoUser.getHdbToken().equals(infoUser.getToken("SYSTEM", "HDB")));
		Assert.assertTrue(!infoUser.getAppToken().isEmpty());
		Assert.assertTrue(infoUser.getAppToken().equals(infoUser.getToken("SYSTEM", "JobScheduler")));
	}


	@Test(expected = UserInfoException.class)
	public void getAttributeNotExisting() throws XSUserInfoException {
		infoUserNoAttr.getAttribute("cost center");
	}

	@Test(expected = XSUserInfoException.class)
	public void testFailServiceInstanceIdNoId() throws XSUserInfoException {
		Assert.assertEquals("abcd1234", infoUserNoAttr.getCloneServiceInstanceId());
	}

	@Test(expected = XSUserInfoException.class)
	public void testFailAdditionalAuthAttrNoAttr() throws XSUserInfoException {
		Assert.assertEquals("abcd1234", infoUserNoAttr.getAdditionalAuthAttribute("external_id"));
	}
	
}
