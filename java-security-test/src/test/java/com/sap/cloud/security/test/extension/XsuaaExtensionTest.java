package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.test.api.SecurityTestContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(XsuaaExtension.class)
public class XsuaaExtensionTest {

	@Test
	void resolveSecurityTestConfigurationParameter(SecurityTestContext context) {
		assertNotNull(context);
		assertThat(context.getWireMockServer().isRunning()).isTrue();
	}
}