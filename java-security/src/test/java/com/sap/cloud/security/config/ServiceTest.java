package com.sap.cloud.security.config;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import static org.assertj.core.api.Assertions.assertThat;

public class ServiceTest {

	@Rule
	public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

	@Before
	public void setUp() {
		environmentVariables.clear("IAS_SERVICE_NAME");
	}

	@Test
	public void getCFNameOfIasWhenEnvironmentVariableIsNotSet_shouldReturnNull() {
		assertThat(Service.IAS.getCFName()).isNull();
	}

	@Test
	public void getCFNameOfXsuaa_shouldReturnCorrectName() {
		assertThat(Service.XSUAA.getCFName()).isEqualTo("xsuaa");
	}

}