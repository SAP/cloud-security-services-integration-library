package com.sap.xs2.security.container;

import static org.junit.Assert.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;

import com.sap.xsa.security.container.XSTokenRequest;

public class XSTokenRequestImplTest {

	private XSTokenRequest request;

	@Before
	public void setUp() throws Exception {
		request = new XSTokenRequestImpl("http://localhost:8080/uaa/oauth/samlUserInfo");
	}

	@Test
	public void test_setTokenEndpoint() throws URISyntaxException {
		URI tokenEndpoint = new URI("http://localhost:8080/uaa/oauth/samlUserInfo");
		request.setTokenEndpoint(tokenEndpoint);
		assertEquals(request.getTokenEndpoint().toString(), "http://localhost:8080/uaa/oauth/samlUserInfo");
	}

	@Test(expected = URISyntaxException.class)
	public void test_setTokenEndpoint_fails_UriSyntax() throws URISyntaxException {
		URI tokenEndpoint = new URI("PC_DEV2::localhost:8080/uaa/oauth/samlUserInfo");
		request.setTokenEndpoint(tokenEndpoint);
	}

	@Test
	public void test_is_user_token_grant_valid() throws Exception {
		assertFalse(request.isValid());
		assertFalse(request.setType(XSTokenRequest.TYPE_USER_TOKEN).isValid());
		assertFalse(request.setClientId("client_id").isValid());
		assertTrue(request.setClientSecret("client_secret").isValid());
	}

	@Test
	public void test_is_client_credentials_grant_valid() throws Exception {
		assertFalse(request.isValid());
		assertFalse(request.setType(XSTokenRequest.TYPE_CLIENT_CREDENTIALS_TOKEN).isValid());
		assertFalse(request.setClientId("client_id").isValid());
		assertTrue(request.setClientSecret("client_secret").isValid());
	}

	@Test
	public void test_additional_authorization_attributes() throws Exception {
		HashMap<String, String> map = new HashMap<>();
		map.put("foo", "bar");
		map.put("key", "value");
		request.setAdditionalAuthorizationAttributes(map);
		assertEquals("bar", request.getAdditionalAuthorizationAttributes().get("foo"));
		assertEquals("value", request.getAdditionalAuthorizationAttributes().get("key"));
		assertFalse(request.getAdditionalAuthorizationAttributes().containsKey("hugo"));
	}

	@Test
	public void test_additional_authorization_attributes_null() throws Exception {
		request.setAdditionalAuthorizationAttributes(null);
		assertNull(request.getAdditionalAuthorizationAttributes());
		HashMap<String, String> map = new HashMap<>();
		request.setAdditionalAuthorizationAttributes(map);
		assertNull(request.getAdditionalAuthorizationAttributes().get(null));
		assertNotNull(request.getAdditionalAuthorizationAttributes());
		/*
		 * assertEquals("bar", request.getAdditionalAuthorizationAttributes().get("foo")); assertEquals("value",
		 * request.getAdditionalAuthorizationAttributes().get("key")); assertFalse(request.getAdditionalAuthorizationAttributes().containsKey("hugo"));
		 */
	}
}
