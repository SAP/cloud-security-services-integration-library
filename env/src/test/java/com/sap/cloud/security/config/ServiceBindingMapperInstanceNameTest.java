package com.sap.cloud.security.config;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor;
import com.sap.cloud.security.config.cf.CFConstants;

class ServiceBindingMapperInstanceNameTest {

	private static ServiceBinding xsuaaBinding;
	private static ServiceBinding xsuaaBindingNoInstanceName;
	private static ServiceBinding iasBinding;

	@BeforeAll
	static void setupClass() throws IOException {
		xsuaaBinding = readServiceBindingFromJson(Service.XSUAA, "/vcapXsuaaServiceSingleBinding.json");
		xsuaaBindingNoInstanceName = readServiceBindingFromJson(Service.XSUAA, "/vcapXsuaaServiceSingleBindingNoName.json");
		iasBinding = readServiceBindingFromJson(Service.IAS, "/vcapIasServiceSingleBinding.json");
	}

	private static ServiceBinding readServiceBindingFromJson(Service service, String jsonPath) throws IOException {
		String vcapJson = IOUtils.resourceToString(jsonPath, UTF_8);
		ServiceBindingAccessor sba = new SapVcapServicesServiceBindingAccessor(any -> vcapJson);

		return sba.getServiceBindings().stream().filter(b -> service.equals(Service.from(b.getServiceName().orElse("")))).findFirst().get();
	}

	@Test
	void getXsuaaConfiguration() {
		OAuth2ServiceConfiguration config = ServiceBindingMapper.mapToOAuth2ServiceConfigurationBuilder(xsuaaBinding).build();
		assertThat(config.getProperty(CFConstants.NAME)).isEqualTo("example-xsuaa");
	}

	@Test
	void getIasConfiguration() {
		OAuth2ServiceConfiguration config = ServiceBindingMapper.mapToOAuth2ServiceConfigurationBuilder(iasBinding).build();
		assertThat(config.getProperty(CFConstants.NAME)).isEqualTo("myservice");
	}
	
	@Test
	void getXsuaaConfigurationNoInstanceName() {
		/*
		 * Ensure that there is no error raised even if no instance name was available (e.g. K8S environment)
		 */
		OAuth2ServiceConfiguration config = ServiceBindingMapper.mapToOAuth2ServiceConfigurationBuilder(xsuaaBindingNoInstanceName).build();
		assertThat(config.getProperty(CFConstants.NAME)).isNull();
	}
}
