package com.sap.cloud.security.xsuaa.extractor;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TokenUtilTest {

	private static String encodedIasToken;
	private static String encodedXsuaaToken;

	@Before
	public void setup() throws IOException {
		encodedIasToken = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);
		encodedXsuaaToken = IOUtils.resourceToString("/token_xsuaa.txt", StandardCharsets.UTF_8);
	}

	@Test
	public void isXsuaaTokenFalseTest() {
		assertFalse(TokenUtil.isXsuaaToken(TokenUtil.decodeJwt(encodedIasToken)));
	}

	@Test
	public void isXsuaaTokenTrueTest() {
		assertTrue(TokenUtil.isXsuaaToken(TokenUtil.decodeJwt(encodedXsuaaToken)));
	}

	@Test
	public void isXchangeEnabledTest() {
		assertFalse(TokenUtil.isIasToXsuaaXchangeEnabled());
	}

}