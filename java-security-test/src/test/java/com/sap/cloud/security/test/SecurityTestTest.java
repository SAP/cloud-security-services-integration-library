package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class SecurityTestTest {

	private SecurityTest cut = new SecurityTest(Service.XSUAA);

	@Test
	public void wireMockServerIsNotRunningAfterTearDown() throws Exception {
		cut.setup();
		cut.tearDown();
		assertThat(cut.wireMockServer.isRunning()).isFalse();
	}

}