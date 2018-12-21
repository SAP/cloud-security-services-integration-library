package com.sap.xs2.security.container;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.sap.xsa.security.container.XSUserInfoException;

public class UserInfoTestClientCredentials {

	private UserInfo infoCc = null;
	private UserInfo infoCcNoAttr = null;

	@Before
	public void setup() throws Exception {
		infoCc = UserInfoTestUtil.createFromJwtFile("/token_cc.txt", "java-hello-world");
		infoCcNoAttr = UserInfoTestUtil.createFromJwtFile("/token_cc_noattr.txt", "java-hello-world");
	}

	@Test(expected = UserInfoException.class)
	public void getLogonNameCc() throws XSUserInfoException {
		infoCc.getLogonName();
	}

	@Test(expected = UserInfoException.class)
	public void getEmailCc() throws XSUserInfoException {
		infoCc.getEmail();
	}

	@Test(expected = UserInfoException.class)
	public void getGivenNameCc() throws XSUserInfoException {
		infoCc.getGivenName();
	}

	@Test(expected = UserInfoException.class)
	public void getFamilyNameCc() throws XSUserInfoException {
		infoCc.getFamilyName();
	}

	@Test(expected = UserInfoException.class)
	public void getOriginCc() throws XSUserInfoException {
		Assert.assertNull(infoCc.getOrigin()); // not in samlUserInfo
	}


	@Test(expected = UserInfoException.class)
	public void getAttributeCc() throws XSUserInfoException {
		infoCc.getAttribute("cost center");
	}

	@Test(expected = UserInfoException.class)
	public void getAttributeCcNotExisting() throws XSUserInfoException {
		infoCcNoAttr.getAttribute("cost center");
	}

	@Test(expected = XSUserInfoException.class)
	public void hasAttributesCc() throws XSUserInfoException {
		infoCc.hasAttributes();
	}

	@Test
	public void getTokenCc() throws XSUserInfoException {
		Assert.assertNotNull("Token must not be null", infoCc.getHdbToken());
		Assert.assertTrue(!infoCc.getHdbToken().isEmpty());
		Assert.assertTrue(infoCc.getHdbToken().equals(infoCc.getToken("SYSTEM", "HDB")));
		Assert.assertTrue(!infoCc.getAppToken().isEmpty());
		Assert.assertTrue(infoCc.getAppToken().equals(infoCc.getToken("SYSTEM", "JobScheduler")));
	}
}
