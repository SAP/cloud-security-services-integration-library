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

	@Test
	public void getCurrentEnvironment_returnsCorrectEnvironment() {
		// TODO 29.11.19 c5295400: extend test when more than one environment is supported
		assertThat(Environments.getCurrentEnvironment().getType()).isEqualTo(Environment.Type.CF);
	}
}