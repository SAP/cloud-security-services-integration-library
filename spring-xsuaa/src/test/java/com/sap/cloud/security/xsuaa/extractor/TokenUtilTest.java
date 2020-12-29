package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.context.ContextConfiguration;

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
		assertFalse(TokenUtil.isXsuaaToken(encodedIasToken));
	}

	@Test
	public void isXsuaaTokenTrueTest() {
		assertTrue(TokenUtil.isXsuaaToken(encodedXsuaaToken));
	}

	@Test
	public void isXchangeEnabledTest(){
		assertFalse(TokenUtil.isIasToXsuaaXchangeEnabled());
	}

}