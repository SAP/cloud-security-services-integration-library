package com.sap.cloud.security.config;

import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import static org.assertj.core.api.Assertions.assertThat;

public class ServiceTest {

	@Rule
	public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

	@Test
	public void getCFName_shouldReturnNull() {
		environmentVariables.clear("IAS_SERVICE_NAME");
		assertThat(Service.IAS.getCFName()).isNull();
	}

	//	TODO only one of the test runs because enums are only initialized once (singleton)
//	@Test
//	public void getCFName_shouldReturnName() {
//		environmentVariables.set("IAS_SERVICE_NAME", "identity-beta");
//		assertThat(Service.IAS.getCFName()).isEqualTo("identity-beta");
//	}

}