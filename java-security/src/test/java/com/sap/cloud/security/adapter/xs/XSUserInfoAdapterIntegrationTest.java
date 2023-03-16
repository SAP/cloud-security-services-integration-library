/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.adapter.xs;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.ServiceBindingEnvironment;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.token.XsuaaScopeConverter;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.xsa.security.container.XSUserInfo;
import com.sap.xsa.security.container.XSUserInfoException;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.TRUSTED_CLIENT_ID_SUFFIX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * This integration test has been ported from the original implementation of
 * XSUserInfo to ensure compatibility.
 */
public class XSUserInfoAdapterIntegrationTest {

	private XSUserInfo infoUser;
	private XSUserInfo infoUserNoAttr;
	private XSUserInfo infoCc;
	private XSUserInfo infoCcNoAttr;
	private XSUserInfo correctEnduserInfo;
	private XSUserInfo correctEnduserInfoWithUaaUser;
	private OAuth2TokenService oAuth2TokenService;
	private OAuth2ServiceConfiguration xsuaaConfiguration;


	@Before
	public void setup() throws XSUserInfoException, IOException, JSONException {
		oAuth2TokenService = Mockito.mock(OAuth2TokenService.class);
		String vcapServices = buildVcapServices("java-hello-world", "default");
		xsuaaConfiguration = (new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> vcapServices))).getXsuaaConfiguration();
		infoUser = createToken(readData("/token_user.txt"));
		infoUserNoAttr = createToken(readData("/token_user_noattr.txt"));
		infoCc = createToken(readData("/token_cc.txt"));
		infoCcNoAttr = createToken(readData("/token_cc_noattr.txt"));
		correctEnduserInfo = createToken(readData("/correctEndUserToken.txt"));
		correctEnduserInfoWithUaaUser = createToken(readData("/correctEndUserTokenUaaUser.txt"));
	}

	private XSUserInfo createToken(String token) {
		String appId = xsuaaConfiguration.getProperty(ServiceConstants.XSUAA.APP_ID);
		XsuaaToken accessToken = new XsuaaToken(token).withScopeConverter(new XsuaaScopeConverter(appId));
		XSUserInfoAdapter xsUserInfoAdapter = new XSUserInfoAdapter(accessToken, xsuaaConfiguration);
		xsUserInfoAdapter.setOAuth2TokenService(oAuth2TokenService);
		return xsUserInfoAdapter;
	}

	@Test
	public void getLogonName() {
		assertEquals("WOLFGANG", infoUser.getLogonName());
	}

	@Test(expected = XSUserInfoException.class)
	public void getLogonNameCc() {
		infoCc.getLogonName();
	}

	@Test
	public void getEmail() {
		assertEquals("WOLFGANG@unknown", infoUser.getEmail());
	}

	@Test(expected = XSUserInfoException.class)
	public void getEmailCc() {
		infoCc.getEmail();
	}

	@Test(expected = XSUserInfoException.class)
	public void getGivenName() {
		infoUser.getGivenName(); // not in token
	}

	@Test(expected = XSUserInfoException.class)
	public void getGivenNameCc() {
		infoCc.getGivenName();
	}

	@Test(expected = XSUserInfoException.class)
	public void getFamilyName() {
		infoUser.getFamilyName(); // not in token
	}

	@Test(expected = XSUserInfoException.class)
	public void getFamilyNameCc() {
		infoCc.getFamilyName();
	}

	@Test
	public void getOrigin() {
		assertEquals("useridp", infoUser.getOrigin());
	}

	@Test(expected = XSUserInfoException.class)
	public void getOriginCc() {
		Assert.assertNull(infoCc.getOrigin()); // not in token
	}

	@Test
	public void getClientId() {
		assertEquals("sb-java-hello-world", infoUser.getClientId());
	}

	@Test
	public void checkScope() {
		assertEquals(false, infoUser.checkScope("cloud_controller.read"));
		assertEquals(true, infoUser.checkScope("java-hello-world.Display"));
	}

	private JSONObject buildBinding(String xsappname, String planName) throws JSONException {
		JSONObject credentials = new JSONObject();
		credentials.put("verificationkey", "key");
		credentials.put(ServiceConstants.XSUAA.APP_ID, xsappname);
		credentials.put(TRUSTED_CLIENT_ID_SUFFIX, xsappname);
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

	private String buildVcapServices(String xsappname1, String planName1, String xsappname2, String planName2)
			throws JSONException {
		JSONObject vcapServices = new JSONObject();
		JSONArray bindingArray = new JSONArray();
		bindingArray.put(buildBinding(xsappname1, planName1));
		bindingArray.put(buildBinding(xsappname2, planName2));
		vcapServices.put("xsuaa", bindingArray);
		return vcapServices.toString();
	}

	@Test
	public void checkLocalScopeVcapServicesOneBinding() throws XSUserInfoException, IOException, JSONException {
		// test default plan binding with default plan token
		String token = readData("/token_user.txt");
		XSUserInfo userInfo = createToken(token);
		Assert.assertFalse(userInfo.checkLocalScope("read"));
		userInfo = createToken(token);
		Assert.assertTrue(userInfo.checkLocalScope("Display"));
		// test application plan binding with default plan token
		userInfo = createToken(token);
		Assert.assertFalse(userInfo.checkLocalScope("read"));
		userInfo = createToken(token);
		Assert.assertTrue(userInfo.checkLocalScope("Display"));
	}

	/**
	 * The method {@link XSUserInfoAdapter#checkLocalScope(String)} does not throw
	 * the {@link XSUserInfoException} when it still can find a valid configuration
	 * in the environment. This is a (breaking) change in contrast to the original
	 * implementation of {@link XSUserInfo}. This test is not applicable but stays
	 * to document what has been changed in the implementation.
	 */
	@Test
	@Ignore
	public void checkLocalScopeVcapServicesTwoBindings() throws XSUserInfoException, IOException, JSONException {
		// test default & application plan binding with default plan token
		String vcapServices = buildVcapServices("cloud_controller", "default",
				"java-hello-world!t5", "application");
		String token = readData("/token_user.txt");
		XSUserInfo userInfo = createToken(token);
		Assert.assertFalse(userInfo.checkLocalScope("read"));
		vcapServices = buildVcapServices("java-hello-world", "default",
				"java-hello-world!t5", "application");
		userInfo = createToken(token);
		Assert.assertTrue(userInfo.checkLocalScope("Display"));

		// test broker & application plan binding with default plan token
		vcapServices = buildVcapServices("cloud_controller!b4", "broker", "java-hello-world!t5", "application");
		userInfo = createToken(token);
		try {
			Assert.assertFalse(userInfo.checkLocalScope("read"));
			fail();
		} catch (XSUserInfoException e) {
			assertEquals("Property xsappname not found in VCAP_SERVICES, must be declared in xs-security.json",
					e.getMessage());
		}
		vcapServices = buildVcapServices("java-hello-world!b4", "broker", "java-hello-world!t5", "application");
		userInfo = createToken(token);
		try {
			Assert.assertFalse(userInfo.checkLocalScope("Display"));
			fail();
		} catch (XSUserInfoException e) {
			assertEquals("Property xsappname not found in VCAP_SERVICES, must be declared in xs-security.json",
					e.getMessage());
		}
		// test two default plan binding with default plan token
		vcapServices = buildVcapServices("cloud_controller", "default", "node-hello-world", "default");
		userInfo = createToken(token);
		try {
			Assert.assertFalse(userInfo.checkLocalScope("read"));
			fail();
		} catch (XSUserInfoException e) {
			assertEquals("Property xsappname not found in VCAP_SERVICES, must be declared in xs-security.json",
					e.getMessage());
		}
		vcapServices = buildVcapServices("cloud_controller", "default", "java-hello-world", "default");
		userInfo = createToken(token);
		try {
			Assert.assertFalse(userInfo.checkLocalScope("Display"));
			fail();
		} catch (XSUserInfoException e) {
			assertEquals("Property xsappname not found in VCAP_SERVICES, must be declared in xs-security.json",
					e.getMessage());
		}
		// test two application plan binding with default plan token
		vcapServices = buildVcapServices("node-hello-world!t5", "application", "java-hello-world!t5", "application");
		userInfo = createToken(token);
		try {
			Assert.assertFalse(userInfo.checkLocalScope("read"));
			fail();
		} catch (XSUserInfoException e) {
			assertEquals("Property xsappname not found in VCAP_SERVICES, must be declared in xs-security.json",
					e.getMessage());
		}
		vcapServices = buildVcapServices("node-hello-world!t5", "application", "java-hello-world!t5", "application");
		userInfo = createToken(token);
		try {
			Assert.assertFalse(userInfo.checkLocalScope("Display"));
			fail();
		} catch (XSUserInfoException e) {
			assertEquals("Property xsappname not found in VCAP_SERVICES, must be declared in xs-security.json",
					e.getMessage());
		}
	}

	@Test
	public void getAttribute() {
		String[] cost_center = infoUser.getAttribute("cost center");
		assertEquals(2, cost_center.length);
		assertEquals("0815", cost_center[0]);
		assertEquals("4711", cost_center[1]);
		String[] country = infoUser.getAttribute("country");
		assertEquals(1, country.length);
		assertEquals("Germany", country[0]);
	}

	@Test(expected = XSUserInfoException.class)
	public void getAttributeNotExisting() {
		infoUserNoAttr.getAttribute("cost center");
	}

	@Test(expected = XSUserInfoException.class)
	public void getAttributeCc() {
		infoCc.getAttribute("cost center");
	}

	@Test(expected = XSUserInfoException.class)
	public void getAttributeCcNotExisting() {
		infoCcNoAttr.getAttribute("cost center");
	}

	@Test
	public void hasAttributes() {
		Assert.assertTrue(infoUser.hasAttributes());
		Assert.assertTrue(!infoUserNoAttr.hasAttributes());
	}

	@Test(expected = XSUserInfoException.class)
	public void hasAttributesCc() {
		infoCc.hasAttributes();
	}

	@Test
	public void testServiceInstanceId() {
		assertEquals("abcd1234", infoUser.getCloneServiceInstanceId());
	}

	@Test(expected = XSUserInfoException.class)
	public void testFailServiceInstanceIdNoId() {
		assertEquals("abcd1234", infoUserNoAttr.getCloneServiceInstanceId());
	}

	@Test
	public void testAdditionalAuthAttr() {
		assertEquals("abcd1234", infoUser.getAdditionalAuthAttribute("external_id"));
	}

	@Test(expected = XSUserInfoException.class)
	public void testFailAdditionalAuthAttrNoAttr() {
		assertEquals("abcd1234", infoUserNoAttr.getAdditionalAuthAttribute("external_id"));
	}

	private String readData(String path) throws IOException {
		return IOUtils.resourceToString("/userInfoIntegration" + path, StandardCharsets.UTF_8);
	}
}
