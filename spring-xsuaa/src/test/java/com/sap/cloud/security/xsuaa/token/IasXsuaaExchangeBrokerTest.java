package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.extractor.IasXsuaaExchangeBroker;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ContextConfiguration(classes = XsuaaServiceConfigurationDefault.class)
public class IasXsuaaExchangeBrokerTest {

	@Autowired
	XsuaaServiceConfiguration serviceConfiguration;

	private static String encodedIasToken;
	private static String encodedXsuaaToken;
	private static IasXsuaaExchangeBroker tokenWrapper;

	@Before
	public void setup() throws IOException {
		encodedIasToken = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);
		encodedXsuaaToken = IOUtils.resourceToString("/token_xsuaa.txt", StandardCharsets.UTF_8);
		tokenWrapper = mock(IasXsuaaExchangeBroker.class);
	}

	@Test
	public void isXsuaaTokenFalseTest() {
		when(tokenWrapper.isXsuaaToken(encodedIasToken)).thenCallRealMethod();
		assertFalse(tokenWrapper.isXsuaaToken(encodedIasToken));
	}

	@Test
	public void isXsuaaTokenTrueTest() {
		when(tokenWrapper.isXsuaaToken(encodedXsuaaToken)).thenCallRealMethod();
		assertTrue(tokenWrapper.isXsuaaToken(encodedXsuaaToken));
	}

}