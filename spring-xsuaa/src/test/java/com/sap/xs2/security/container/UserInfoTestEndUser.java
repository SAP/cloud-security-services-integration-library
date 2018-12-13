package com.sap.xs2.security.container;

import org.junit.Before;
import org.junit.Test;

import com.sap.xsa.security.container.XSUserInfoException;

public class UserInfoTestEndUser {

	private UserInfo correctEnduserInfo = null;
	private UserInfo correctEnduserInfoWithUaaUser = null;

	@Before
	public void setup() throws Exception {
		correctEnduserInfo = UserInfoTestUtil.createFromJwtFile("/correctEndUserToken.txt", "java-hello-world");
		correctEnduserInfoWithUaaUser = UserInfoTestUtil.createFromJwtFile("/correctEndUserTokenUaaUser.txt", "java-hello-world");
	}



	@Test(expected = UserInfoException.class)
	public void requestTokenForClientTestNoUaaUserScope() throws XSUserInfoException {
		correctEnduserInfo.requestTokenForClient("foo", "bar", "foobar");
	}

	@Test(expected = UserInfoException.class)
	public void requestTokenForClientTestInvalidClientId() throws XSUserInfoException {
		correctEnduserInfoWithUaaUser.requestTokenForClient(null, "foo", "bar");
	}

	@Test(expected = UserInfoException.class)
	public void requestTokenForClientTestInvalidClientSecret() throws XSUserInfoException {
		correctEnduserInfoWithUaaUser.requestTokenForClient("foo", null, "bar");
	}

	@Test(expected = UserInfoException.class)
	public void requestTokenForClientTestInvalidUaaUrl() throws XSUserInfoException {
		correctEnduserInfoWithUaaUser.requestTokenForClient("foo", "bar", null);
	}
}
