package com.sap.cloud.security.config;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class EnvironmentsTest {

	@Test
	public void getCurrentEnvironment_returnsOnlySingleInstance() {
		Environment firstEnvironment = Environments.getCurrentEnvironment();
		Environment secondEnvironment = Environments.getCurrentEnvironment();

		assertThat(firstEnvironment).isSameAs(secondEnvironment);
	}
}