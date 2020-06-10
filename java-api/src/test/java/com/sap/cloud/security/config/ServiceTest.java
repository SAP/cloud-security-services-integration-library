package com.sap.cloud.security.config;

import org.junit.Test;

import static org.assertj.core.api.Assertions.*;

public class ServiceTest {

	/**
	 * This test assumes that the system variable "IAS_SERVICE_NAME" is not set. It
	 * should be removed as soon as {@link Service#IAS} is supported.
	 */
	@Test
	public void getCFNameOfIasWhenEnvironmentVariableIsNotSet_shouldReturnNull() {
		assertThat(Service.IAS.getCFName()).isNull();
	}

	@Test
	public void getCFNameOfXsuaa_shouldReturnCorrectName() {
		assertThat(Service.XSUAA.getCFName()).isEqualTo("xsuaa");
	}

}