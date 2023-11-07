/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p> <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.cf;

import static com.sap.cloud.security.config.cf.CFConstants.CLIENT_SECRET;
import static com.sap.cloud.security.config.cf.CFConstants.CREDENTIALS;
import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;
import static com.sap.cloud.security.config.cf.CFConstants.VCAP_APPLICATION;
import static com.sap.cloud.security.config.cf.CFConstants.VCAP_SERVICES;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.assertj.core.api.Assertions;
import org.junit.Test;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants.Plan;
import com.sap.cloud.security.config.cf.CFConstants.XSUAA;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;

public class CFEnvironmentTest {

	private final String vcapXsuaa;
	private final String vcapMultipleXsuaa;
	private final String vcapFourXsuaa;
	private final String vcapIas;
	private final String vcapXsa;

	public CFEnvironmentTest() throws IOException {
		vcapXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
		vcapMultipleXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceMultipleBindings.json", UTF_8);
		vcapIas = IOUtils.resourceToString("/vcapIasServiceSingleBinding.json", UTF_8);
		vcapXsa = IOUtils.resourceToString("/vcapXsuaaXsaSingleBinding.json", UTF_8);
		vcapFourXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceFourBindings.json", UTF_8);
	}

	@Test
	public void getInstance() {
		assertThat(CFEnvironment.getInstance()).isNotSameAs(CFEnvironment.getInstance());

		final CFEnvironment cut = CFEnvironment.getInstance();
		assertThat(cut.getType()).isEqualTo(Environment.Type.CF);
	}

	@Test
	public void getCFServiceConfigurationAndCredentialsAsMap() {
		JsonObject serviceJsonObject = new DefaultJsonObject(vcapXsuaa).getJsonObjects(Service.XSUAA.getCFName()).get(0);
		Map<String, String> xsuaaConfigMap = serviceJsonObject.getKeyValueMap();
		Map<String, String> credentialsMap = serviceJsonObject.getJsonObject(CREDENTIALS).getKeyValueMap();

		assertThat(xsuaaConfigMap).hasSize(4);
		assertThat(credentialsMap).hasSize(10).containsEntry(CLIENT_SECRET, "secret");
	}

	private static class MockEnvironment {
		private String vcapServices = "{}";
		private String vcapApplication = "{}";

		public MockEnvironment(String vcapServices) {
			this.vcapServices = vcapServices;
		}

		public MockEnvironment(String vcapServices, String vcapApplication) {
			this.vcapServices = vcapServices;
			this.vcapApplication = vcapApplication;
		}
		
		public String getEnv(String name) {
			if (name == null) {
				Assertions.fail("Environment request detected without name value provided");
				return null; // never reached
			}
			if (VCAP_APPLICATION.equals(name)) {
				return this.vcapApplication;
			}
			if (VCAP_SERVICES.equals(name)) {
				return this.vcapServices;
			}
			Assertions.fail(String.format("Unknown environment variable %s requested", name));
			return null; // never reached
		}
	}

	@Test
	public void getConfigurationOfOneIasInstance() {
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(vcapIas)::getEnv);

		assertThat(cut.getIasConfiguration()).isSameAs(cut.getIasConfiguration());
		assertThat(cut.getIasConfiguration().getService()).isEqualTo(Service.IAS);
		assertThat(cut.getIasConfiguration().getClientId()).isEqualTo("T000310");
		assertThat(cut.getIasConfiguration().getClientSecret()).startsWith("pCghfbrL");
		assertThat(cut.getIasConfiguration().getUrl()).hasToString("https://myauth.com");
		assertThat(cut.getIasConfiguration().isLegacyMode()).isFalse();

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isNull();
		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(0);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(1);
	}

	@Test
	public void getConfigurationOfOneXsuaaInstance() {
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(vcapXsuaa)::getEnv);

		assertThat(cut.getXsuaaConfiguration()).isSameAs(cut.getXsuaaConfiguration());
		assertThat(cut.getXsuaaConfiguration().getService()).isEqualTo(Service.XSUAA);
		assertThat(cut.getXsuaaConfiguration().getClientId()).isEqualTo("clientId");
		assertThat(cut.getXsuaaConfiguration().getClientSecret()).isEqualTo("secret");
		assertThat(cut.getXsuaaConfiguration().getProperty(XSUAA.UAA_DOMAIN)).isEqualTo("auth.com");
		assertThat(cut.getXsuaaConfiguration().getProperty(XSUAA.APP_ID)).isEqualTo("java-hello-world");
		assertThat(cut.getXsuaaConfiguration().getUrl()).hasToString("https://paastenant.auth.com");
		assertThat(cut.getXsuaaConfiguration().isLegacyMode()).isFalse();

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(1);
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isSameAs(cut.getXsuaaConfiguration());

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(1);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);

		assertThat(cut.getIasConfiguration()).isNull();
	}

	@Test
	public void getConfigurationOfXsuaaInstanceInXsaSystem() {
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(vcapXsa, "{\"xs_api\": \"anyvalue\"}")::getEnv);

		assertThat(cut.getXsuaaConfiguration().getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(cut.getXsuaaConfiguration().getProperty(SERVICE_PLAN))).isEqualTo(Plan.SPACE);
		assertThat(cut.getXsuaaConfiguration().getClientId()).isEqualTo("sb-java-hello-world!i1");
		assertThat(cut.getXsuaaConfiguration().getProperty(XSUAA.APP_ID)).isEqualTo("java-hello-world!i1");
		assertThat(cut.getXsuaaConfiguration().getClientSecret()).startsWith("fxnWLHqLh6KC0Wp/bbv8Gwbu50OEbpS");
		assertThat(cut.getXsuaaConfiguration().getUrl()).hasToString("https://xsa-test.c.eu-de-2.cloud.sap:30132/uaa-security");
		assertThat(cut.getXsuaaConfiguration().isLegacyMode()).isTrue();

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(1);
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isSameAs(cut.getXsuaaConfiguration());

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(1);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
	}

	@Test
	public void getConfigurationOfMultipleInstance() {
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(vcapMultipleXsuaa)::getEnv);

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(2);
		OAuth2ServiceConfiguration appServConfig = cut.getXsuaaConfiguration();
		OAuth2ServiceConfiguration brokerServConfig = cut.getXsuaaConfigurationForTokenExchange();

		assertThat(appServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(appServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.APPLICATION);

		assertThat(brokerServConfig).isNotEqualTo(appServConfig);
		assertThat(brokerServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(brokerServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaConfigurationForTokenExchange());

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
		
		final List<OAuth2ServiceConfiguration> serviceConfigList = cut.getServiceConfigurationsAsList().get(Service.XSUAA);
		assertThat(serviceConfigList.size()).isEqualTo(2);

		assertThat(serviceConfigList.get(0)).isSameAs(appServConfig);
		assertThat(serviceConfigList.get(1)).isSameAs(brokerServConfig);
	}

	@Test
	public void getConfigurationByPlan() {
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(vcapMultipleXsuaa)::getEnv);

		OAuth2ServiceConfiguration appServConfig = cut.loadForServicePlan(Service.XSUAA, Plan.APPLICATION);
		OAuth2ServiceConfiguration brokerServConfig = cut.loadForServicePlan(Service.XSUAA, Plan.BROKER);

		assertThat(Plan.from(appServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.APPLICATION);
		assertThat(appServConfig).isSameAs(cut.getXsuaaConfiguration());

		assertThat(Plan.from(brokerServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaConfigurationForTokenExchange());
	}

	@Test
	public void getXsuaaServiceConfiguration_usesSystemProperties() {
		System.setProperty(VCAP_SERVICES, vcapMultipleXsuaa);

		final CFEnvironment cut = CFEnvironment.getInstance();
		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaConfiguration();

		assertThat(serviceConfiguration).isNotNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(2);

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
	}

	@Test
	public void getXsuaaServiceConfiguration_prioritizesSystemProperties() {
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(vcapXsuaa)::getEnv, new MockEnvironment(vcapMultipleXsuaa)::getEnv);

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaConfiguration();

		assertThat(serviceConfiguration).isNotNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(2);

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
	}

	@Test
	public void getServiceConfiguration_vcapServicesNotAvailable_returnsNull() {
		final CFEnvironment cut = CFEnvironment.getInstance((str) -> null);

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isZero();
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isNull();
		assertThat(cut.loadForServicePlan(Service.IAS, Plan.DEFAULT)).isNull();
		assertThat(CFEnvironment.getInstance().getXsuaaConfiguration()).isNull();
		assertThat(cut.getIasConfiguration()).isNull();

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(0);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
	}

	@Test
	public void loadXsuaa_UseApplicationOverBroker() {
		final String allBindings = "{\"xsuaa\": [" + "{\"plan\": \"broker\", \"credentials\": {}}," + "{\"plan\": \"application\", \"credentials\": {}}]}";
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(allBindings)::getEnv);

		OAuth2ServiceConfiguration config = cut.getXsuaaConfiguration();
		assertThat(Plan.from(config.getProperty(SERVICE_PLAN))).isEqualTo(Plan.APPLICATION);
	}

	@Test
	public void loadXsuaaLegacy() {
		final String allBindings = "{\"xsuaa\": [" + "{\"plan\": \"default\", \"credentials\": {}}," + "{\"plan\": \"space\", \"credentials\": {}}]}";
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(allBindings)::getEnv);

		OAuth2ServiceConfiguration config = cut.getXsuaaConfiguration();
		assertThat(Plan.from(config.getProperty(SERVICE_PLAN))).isEqualTo(Plan.SPACE);

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
	}

	@Test
	public void getXsuaaConfiguration_noVcapServices_doesNotThrowExceptions() {
		final CFEnvironment cut = CFEnvironment.getInstance((any) -> null);

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isZero();

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(0);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
	}

	@Test
	public void getXsuaaConfiguration_vcapServicesEmptyString_doesNotThrowExceptions() {
		final CFEnvironment cut = CFEnvironment.getInstance((any) -> "");

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isZero();

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(0);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
	}

	@Test
	public void getXsuaaConfiguration_vcapServicesEmptyJson_doesNotThrowExceptions() {
		final CFEnvironment cut = CFEnvironment.getInstance((any) -> "{}");

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isZero();

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(0);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
	}

	@Test
	public void getXsuaaConfiguration_vcapServicesNoServiceName_doesNotThrowExceptions() {
		String xsuaaBinding = "{\"\": [{ \"credentials\": null }]}";
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(xsuaaBinding)::getEnv);
		assertThat(cut.getXsuaaConfiguration()).isNull();

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(0);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);
	}
	
	@Test
	public void getConfigurationOfFourInstances() {
		final CFEnvironment cut = CFEnvironment.getInstance(new MockEnvironment(vcapFourXsuaa)::getEnv);

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(4);
		OAuth2ServiceConfiguration appServConfig = cut.getXsuaaConfiguration();
		OAuth2ServiceConfiguration brokerServConfig = cut.getXsuaaConfigurationForTokenExchange();

		assertThat(appServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(appServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.APPLICATION);

		assertThat(brokerServConfig).isNotEqualTo(appServConfig);
		assertThat(brokerServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(brokerServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaConfigurationForTokenExchange());

		assertThat(cut.getServiceConfigurationsAsList()).isNotNull();
		assertThat(cut.getServiceConfigurationsAsList().size()).isEqualTo(2);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.XSUAA).size()).isEqualTo(4);
		assertThat(cut.getServiceConfigurationsAsList().get(Service.IAS).size()).isEqualTo(0);

		final List<OAuth2ServiceConfiguration> xsuaaConfigurations = cut.getServiceConfigurationsAsList().get(Service.XSUAA);
		
		assertThat(xsuaaConfigurations.stream().anyMatch(e -> e == appServConfig)).isTrue();
		assertThat(xsuaaConfigurations.stream().anyMatch(e -> e == brokerServConfig)).isTrue();
	}
}