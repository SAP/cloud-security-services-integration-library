package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvParser;
import com.sap.cloud.security.config.cf.CFOAuth2ServiceConfiguration;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

import static com.sap.cloud.security.config.cf.CFConstants.Plan.APPLICATION;
import static com.sap.cloud.security.config.cf.CFConstants.ServiceType.IAS;
import static com.sap.cloud.security.config.cf.CFConstants.ServiceType.XSUAA;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class CFEnvParserTest {

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
	public void load_returnsCorrectConfiguration() {
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
	public void loadAll_serviceTypeIsOnlyBinding_returnsSingleConfigurationInList() {
		List<CFOAuth2ServiceConfiguration> configurations = cutSingleBinding.loadAll(XSUAA);

		assertThat(configurations).hasSize(1);
	}

	@Test
	public void load_onlyBinding_returnsCorrectConfiguration() {
		CFOAuth2ServiceConfiguration configuration = cutSingleBinding.load(XSUAA);

		assertThat(configuration).isNotNull();
		assertThat(configuration.getPlan()).isEqualTo(APPLICATION);
	}

	@Test
	public void load_emptyBindings_isNull() {
		CFOAuth2ServiceConfiguration configuration = new CFEnvParser("{xsuaa: []}").load(XSUAA);

		assertThat(configuration).isNull();
	}

	@Test
	public void loadAll_emptyBindings_isEmptyList() {
		List<CFOAuth2ServiceConfiguration> configurations = new CFEnvParser("{xsuaa: []}").loadAll(XSUAA);

		assertThat(configurations).isEmpty();
	}
}