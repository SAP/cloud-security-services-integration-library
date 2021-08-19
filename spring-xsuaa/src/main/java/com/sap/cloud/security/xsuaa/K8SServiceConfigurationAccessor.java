package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConfigurationAccessor;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceManagerService;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2SMService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

/**
 * The K8s Service Configuration accessor.
 */
public class K8SServiceConfigurationAccessor implements ServiceConfigurationAccessor {

	private static final Logger LOGGER = LoggerFactory.getLogger(K8SServiceConfigurationAccessor.class);
	private static final String DEFAULT_XSUAA_PATH = "/etc/secrets/sapcp/xsuaa";
	private static final String DEFAULT_SM_PATH = "/etc/secrets/sapcp/service-manager";
	private final String customXsuaaPath;
	private final String customSMPath;
	private OAuth2ServiceManagerService smService;


	/**
	 * Instantiates a new K8s secrets' files accessor with default paths. IAS -
	 * /etc/secrets/sapcp/ias XSUAA - /etc/secrets/sapcp/xsuaa
	 */
	public K8SServiceConfigurationAccessor() {
		this(DEFAULT_XSUAA_PATH, DEFAULT_SM_PATH, new RestTemplate());
	}

	/**
	 * Instantiates a new K8s secrets' files accessor with user defined paths.
	 *
	 * @param customXsuaaPath
	 *            the custom xsuaa path
	 */
	public K8SServiceConfigurationAccessor(@Nullable String customXsuaaPath, @Nullable String customSMPath, RestTemplate restTemplate) {
		this.customXsuaaPath = customXsuaaPath;
		this.customSMPath = customSMPath;
		this.smService = new XsuaaOAuth2SMService(loadServiceManagerConfig(), restTemplate);
	}

	public void setSmService(OAuth2ServiceManagerService smService) {
		this.smService = smService;
	}

	@Override
	@Nullable
	public Properties getXsuaaServiceConfiguration() {
		Map<String, Properties> xsuaaPropertiesByPlan = loadXsuaaConfig();
		return Optional.ofNullable(xsuaaPropertiesByPlan.get(CFConstants.Plan.APPLICATION.name()))
				.orElse(Optional.ofNullable(xsuaaPropertiesByPlan.get(CFConstants.Plan.BROKER.name()))
						.orElse(Optional.ofNullable(xsuaaPropertiesByPlan.get(CFConstants.Plan.SPACE.name()))
								.orElse(Optional.ofNullable(xsuaaPropertiesByPlan.get(CFConstants.Plan.DEFAULT.name()))
										.orElse(null))));
	}

	@Override
	public Properties getIasServiceConfiguration() {
		throw new UnsupportedOperationException("IAS is not supported");
	}

	private Map<String, Properties> loadXsuaaConfig() {
		Map<String, Properties> allServices = new HashMap<>();
		File[] serviceBindings = getXsuaaBindings();
		if (serviceBindings != null){
			LOGGER.debug("Found {} Xsuaa service bindings", serviceBindings.length);
			for (File binding : serviceBindings){
				List<File> bindingFiles = getBindingFiles(binding);
				Properties xsuaaProperties= extractServiceProperties(bindingFiles);
				allServices.put(binding.getName(), xsuaaProperties);
			}
		} else {
			LOGGER.warn("No service bindings for Xsuaa were found.");
		}
		return mapXsuaaServicePlans(allServices);
	}

	@Nullable
	private File[] getXsuaaBindings() {
		return new File(customXsuaaPath != null ? customXsuaaPath : DEFAULT_XSUAA_PATH).listFiles();
	}

	private static List<File> getBindingFiles(@Nonnull File binding) {
		File [] bindingFiles = new File(binding.getPath()).listFiles();
		if (bindingFiles == null || bindingFiles.length == 0) {
			LOGGER.warn("No service binding files were found for {}", binding.getName());
			return Collections.emptyList();
		}
		return Arrays.stream(bindingFiles).filter(File::isFile)
				.collect(Collectors.toList());
	}

	private static Properties extractServiceProperties(List<File> servicePropertiesList) {
		Properties serviceBindingProperties = new Properties();
		for (final File property : servicePropertiesList) {
			try {
				final List<String> lines = getLinesFromFile(property);
				serviceBindingProperties.put(property.getName(), String.join("\\n", lines));
			} catch (IOException ex) {
				LOGGER.error("Failed to read secrets files", ex);
				return serviceBindingProperties;
			}
		}
		LOGGER.debug("K8s secrets: {}", serviceBindingProperties);
		return serviceBindingProperties;
	}

	@Nonnull
	private static List<String> getLinesFromFile(File property) throws IOException {
		return Files.readAllLines(Paths.get(property.getAbsolutePath()));
	}

	@Nullable
	private OAuth2ServiceConfiguration loadServiceManagerConfig(){
		File[] serviceBindings = new File(customSMPath != null ? customSMPath : DEFAULT_SM_PATH).listFiles();
		if (serviceBindings == null || serviceBindings.length == 0){
			LOGGER.warn("No service-manager binding was found in {}", customSMPath == null ? DEFAULT_SM_PATH : customSMPath);
			return null;
		}
		List<File> bindingFiles = getBindingFiles(serviceBindings[0]);
		Properties smProperties = extractServiceProperties(bindingFiles);
		return new ServiceManagerConfiguration(smProperties);
	}

	private Map<String, Properties> mapXsuaaServicePlans(Map<String, Properties> allXsuaaServices) {
		Map<String, Properties> allXsuaaServicesWithPlans = new HashMap<>();//<planName, config>

		//TODO duplicate code in K8SServiceConfigurationAccessor.java lines 143ff
		if (allXsuaaServices.isEmpty()){
			return allXsuaaServices;
		}
		Map<String, String> serviceInstancePlans = smService.getServiceInstancePlans();//<xsuaaName, planName>
		if (serviceInstancePlans.isEmpty()){
			LOGGER.warn("Cannot map Xsuaa services with plans, no plans were fetched from service manager");
			return allXsuaaServicesWithPlans;
		}
		allXsuaaServices.keySet().forEach(k-> allXsuaaServicesWithPlans.put(serviceInstancePlans.get(k).toUpperCase(), allXsuaaServices.get(k)));
		return allXsuaaServicesWithPlans;
	}

	private static class ServiceManagerConfiguration implements OAuth2ServiceConfiguration {

		private final Properties properties;

		public ServiceManagerConfiguration(Properties properties) {
			this.properties = properties;
		}

		@Override
		public String getClientId() {
			return properties.getProperty(CFConstants.CLIENT_ID);
		}

		@Override
		public String getClientSecret() {
			return properties.getProperty(CFConstants.CLIENT_SECRET);
		}

		@Override
		public URI getUrl() {
			return URI.create(properties.getProperty(CFConstants.URL));
		}

		@Nullable
		@Override
		public String getProperty(String name) {
			return properties.getProperty(name);
		}

		@Override
		public Map<String, String> getProperties() {
			throw new IllegalStateException("getProperties method is not currently supported");
		}

		@Override
		public boolean hasProperty(String name) {
			return properties.containsKey(name);
		}

		@Override
		public Service getService() {
			throw new IllegalStateException("getService method is not currently supported");
		}

		@Override
		public boolean isLegacyMode() {
			return false;
		}
	}

}
