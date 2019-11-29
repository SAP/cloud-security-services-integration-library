package com.sap.cloud.security.config;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class EnvironmentsTest {

	@Test
	public void getCurrent_returnsOnlySingleInstance() {
		Environment firstEnvironment = Environments.getCurrent();
		Environment secondEnvironment = Environments.getCurrent();

		assertThat(firstEnvironment).isSameAs(secondEnvironment);
	}

	@Test
	public void getCurrent_returnsCorrectEnvironment() {
		// TODO 29.11.19 c5295400: extend test when more than one environment is supported
		assertThat(Environments.getCurrent().getType()).isEqualTo(Environment.Type.CF);
	}
}