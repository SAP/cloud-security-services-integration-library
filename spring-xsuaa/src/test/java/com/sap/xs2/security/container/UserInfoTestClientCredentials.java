package com.sap.xs2.security.container;

import org.json.JSONArray;
import org.json.JSONException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.sap.xsa.security.container.XSUserInfoException;

import net.minidev.json.JSONObject;

public class UserInfoTestClientCredentials {

	private UserInfo infoCc = null;
	private UserInfo infoCcNoAttr = null;

	@Before
	public void setup() throws Exception {
		infoCc = UserInfoTestUtil.loadJwt("/token_cc.txt", "java-hello-world");
		infoCcNoAttr = UserInfoTestUtil.loadJwt("/token_cc_noattr.txt", "java-hello-world");

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
		Assert.assertNull(infoCc.getOrigin()); // not in token
	}

	private JSONObject buildBinding(String xsappname, String planName) throws JSONException {
		JSONObject credentials = new JSONObject();
		credentials.put("clientid", "testClient");
		credentials.put("identityzoneid", "demo");
		credentials.put("verificationkey", "key");
		credentials.put("xsappname", xsappname);
		JSONObject binding = new JSONObject();
		binding.put("name", planName + "-uaa");
		binding.put("label", "xsuaa");
		binding.put("tags", new JSONArray().put("xsuaa"));
		binding.put("plan", planName);
		binding.put("credentials", credentials);
		return binding;
	}

	private String buildVcapServices(String xsappname, String planName) throws JSONException {
		JSONObject vcapServices = new JSONObject();
		JSONArray bindingArray = new JSONArray();
		bindingArray.put(buildBinding(xsappname, planName));
		vcapServices.put("xsuaa", bindingArray);
		return vcapServices.toString();
	}

	private String buildVcapServices(String xsappname1, String planName1, String xsappname2, String planName2) throws JSONException {
		JSONObject vcapServices = new JSONObject();
		JSONArray bindingArray = new JSONArray();
		bindingArray.put(buildBinding(xsappname1, planName1));
		bindingArray.put(buildBinding(xsappname2, planName2));
		vcapServices.put("xsuaa", bindingArray);
		return vcapServices.toString();
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
