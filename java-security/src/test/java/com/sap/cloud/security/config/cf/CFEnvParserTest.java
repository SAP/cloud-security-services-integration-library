package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

import static com.sap.cloud.security.config.cf.CFConstants.Plan.APPLICATION;
import static com.sap.cloud.security.config.cf.CFConstants.Plan.BROKER;
import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class CFEnvParserTest { // Xsuaa

	private static final String EMPTY_XSUAA_BINDINGS = "{iasb: []}";

	private final CFEnvParser cutMultipleBindings;
	private final CFEnvParser cutSingleBinding;

	public CFEnvParserTest() throws IOException {
		String multipleBindingsJson = IOUtils.resourceToString("/vcapXsuaaServiceMultipleBindings.json", UTF_8);
		cutMultipleBindings = new CFEnvParser(multipleBindingsJson);

		String singleBindingJsonString = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
		cutSingleBinding = new CFEnvParser(singleBindingJsonString);
	}

	@Test
	public void loadAll_serviceTypeExists_returnsAllConfigurations() {
		List<CFOAuth2ServiceConfiguration> configurations = cutMultipleBindings.loadAll(XSUAA);

		assertThat(configurations).hasSize(2);
	}

	@Test
	public void loadAll_serviceTypeDoesNotExist_returnsEmptyList() {
		List<CFOAuth2ServiceConfiguration> configurations = cutMultipleBindings.loadAll(IAS);

		assertThat(configurations).isEmpty();
	}

	@Test
	public void load_returnsApplicationConfiguration_inCaseOfMultipleBindings() {
		CFOAuth2ServiceConfiguration configuration = cutMultipleBindings.load(XSUAA);

		assertThat(configuration).isNotNull();
		assertThat(configuration.getPlan()).isEqualTo(APPLICATION);
	}

	@Test
	public void load_nonExistentServiceType_returnsNull() {
		CFOAuth2ServiceConfiguration configuration = cutMultipleBindings.load(IAS);

		assertThat(configuration).isNull();
	}

	@Test
	public void load_onlySingleBinding_returnsCorrectConfiguration() {
		CFOAuth2ServiceConfiguration configuration = cutSingleBinding.load(XSUAA);

		assertThat(configuration).isNotNull();
		assertThat(configuration.getPlan()).isEqualTo(BROKER);
	}

	@Test
	public void load_noServiceBindings_isNull() {
		CFOAuth2ServiceConfiguration configuration = new CFEnvParser(EMPTY_XSUAA_BINDINGS).load(XSUAA);

		assertThat(configuration).isNull();
	}

	@Test
	public void loadAll_noServiceBindings_isEmptyList() {
		List<CFOAuth2ServiceConfiguration> configurations = new CFEnvParser(EMPTY_XSUAA_BINDINGS).loadAll(XSUAA);

		assertThat(configurations).isEmpty();
	}

	@Test
	public void loadByPlan_configurationWithPlanExists_returnsConfiguration() {
		OAuth2ServiceConfiguration configuration = cutMultipleBindings.loadByPlan(XSUAA, APPLICATION);

		assertThat(configuration).isNotNull();
	}

	@Test
	public void loadByPlan_configurationPlanDoesNotExist_returnsNull() {
		OAuth2ServiceConfiguration configuration = cutSingleBinding.loadByPlan(XSUAA, APPLICATION);

		assertThat(configuration).isNull();
	}
}