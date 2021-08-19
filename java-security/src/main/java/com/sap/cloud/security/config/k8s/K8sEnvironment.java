/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2SMService;
import com.sap.cloud.security.xsuaa.client.OAuth2SMService;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.k8s.K8sConstants.*;

/**
 * Loads the OAuth configuration ({@link OAuth2ServiceConfiguration}) of a
 * supported identity {@link Service} in the Kubernetes Environment by
 * accessing defaults service secrets paths "/etc/secrets/sapcp/xsuaa" for Xsuaa service or "/etc/secrets/sapcp/ias" for .
 * IAS service
 */
public class K8sEnvironment implements Environment {

    private static final Logger LOGGER = LoggerFactory.getLogger(K8sEnvironment.class);

    private static K8sEnvironment instance;
    private static String customXsuaaPath;
    private static String customIasPath;
    private static String customSMPath;
    private static CloseableHttpClient httpClient;

    private Map<Service, Map<String, OAuth2ServiceConfiguration>> serviceConfigurations;
    private OAuth2ServiceConfiguration serviceManagerConfigurations;
    private UnaryOperator<String> systemEnvironmentProvider;
    private UnaryOperator<String> systemPropertiesProvider;
    private static OAuth2SMService smService;

    private K8sEnvironment() {}

    public static K8sEnvironment getInstance() {
        return getInstance(System::getenv, System::getProperty);
    }

    public static K8sEnvironment getInstance(UnaryOperator<String> systemEnvironmentProvider,
                                            UnaryOperator<String> systemPropertiesProvider) {
        if (instance == null) {
            instance = new K8sEnvironment();
            instance.systemEnvironmentProvider = systemEnvironmentProvider;
            instance.systemPropertiesProvider = systemPropertiesProvider;
            instance.serviceManagerConfigurations = loadServiceManagerConfig();
            if (instance.serviceManagerConfigurations != null) {
                smService = new DefaultOAuth2SMService(instance.serviceManagerConfigurations, httpClient);
            }
            instance.serviceConfigurations = loadAll();
        }
        return instance;
    }

    public static K8sEnvironment getInstance(@Nullable String customXsuaaPath, @Nullable String customIasPath, @Nullable String customSMPath, @Nullable CloseableHttpClient httpClient) {
        K8sEnvironment.customXsuaaPath = customXsuaaPath;
        K8sEnvironment.customIasPath = customIasPath;
        K8sEnvironment.customSMPath = customSMPath;
        K8sEnvironment.httpClient = httpClient;

        return getInstance(System::getenv, System::getProperty);
    }

    private static Map<Service, Map<String, OAuth2ServiceConfiguration>> loadAll() {
        Map<Service, Map<String, OAuth2ServiceConfiguration>> serviceConfigurations = new HashMap<>(); // NOSONAR
        Map<String, OAuth2ServiceConfiguration> allXsuaaServices = loadOauth2ServiceConfig(Service.XSUAA);
        Map<String, OAuth2ServiceConfiguration>  allIasServices = loadOauth2ServiceConfig(Service.IAS);

        serviceConfigurations.put(Service.XSUAA, mapXsuaaServicePlans(allXsuaaServices));
        serviceConfigurations.put(Service.IAS, allIasServices);
        return serviceConfigurations;
    }

    private static Map<String, OAuth2ServiceConfiguration> mapXsuaaServicePlans(Map<String, OAuth2ServiceConfiguration> allXsuaaServices) {
        Map<String, OAuth2ServiceConfiguration> allXsuaaServicesWithPlans = new HashMap<>();//<planName, config>
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

    @Nullable
    private static OAuth2ServiceConfiguration loadServiceManagerConfig(){
        File[] serviceBindings = new File(customSMPath != null ? customSMPath : DEFAULT_SERVICE_MANAGER_PATH).listFiles();
        if (serviceBindings == null){
            LOGGER.warn("No service-manager binding was found in {}", DEFAULT_SERVICE_MANAGER_PATH);
            return null;
        }
        Map<String, String> smPropertiesMap = getServiceProperties(serviceBindings[0]);
        return OAuth2ServiceConfigurationBuilder.forService(XSUAA).withProperties(smPropertiesMap).build();
    }

    private static Map<String, OAuth2ServiceConfiguration> loadOauth2ServiceConfig(Service service) {
        Map<String, OAuth2ServiceConfiguration> allServices = new HashMap<>();
        File[] serviceBindings = getServiceBindings(service);
        if (serviceBindings != null){
            LOGGER.debug("Found {} {} service bindings", serviceBindings.length, service);
            for (File binding : serviceBindings){
                Map<String, String> servicePropertiesMap = getServiceProperties(binding);
                OAuth2ServiceConfiguration config = OAuth2ServiceConfigurationBuilder.forService(service)
                        .withProperties(servicePropertiesMap)
                        .build();
                allServices.put(binding.getName(), config);
            }
        } else {
            LOGGER.warn("No service bindings for {} service was found.", service);
        }
        return allServices;
    }

    @Nonnull
    @Override
    public Type getType() {
        return Type.KUBERNETES;
    }

    @Nullable
    @Override
    public OAuth2ServiceConfiguration getXsuaaConfiguration() {
        Map<String, OAuth2ServiceConfiguration> xsuaaPlans = serviceConfigurations.get(XSUAA);
        return Optional.ofNullable(xsuaaPlans.get(CFConstants.Plan.APPLICATION.name()))
                .orElse(Optional.ofNullable(xsuaaPlans.get(CFConstants.Plan.BROKER.name()))
                        .orElse(Optional.ofNullable(xsuaaPlans.get(CFConstants.Plan.SPACE.name()))
                                .orElse(Optional.ofNullable(xsuaaPlans.get(CFConstants.Plan.DEFAULT.name()))
                                        .orElse(null))));

    }

    @Nullable
    @Override
    public OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange() {
        return Optional.ofNullable(serviceConfigurations.get(XSUAA).get(CFConstants.Plan.BROKER.name())).orElse(null);
    }

    @Nullable
    @Override
    public OAuth2ServiceConfiguration getIasConfiguration() {
        Optional<Map.Entry<String, OAuth2ServiceConfiguration>> iasConfigEntry = serviceConfigurations.get(IAS).entrySet().stream().findFirst();
        return iasConfigEntry.map(Map.Entry::getValue).orElse(null);
    }

    @Override
    public int getNumberOfXsuaaConfigurations() {
        return getServiceBindings(XSUAA) != null ? getServiceBindings(XSUAA).length : 0;
    }

    @Nullable
    private static File[] getServiceBindings(Service service) {
        if (service == Service.XSUAA){
            if (customXsuaaPath != null) {
                LOGGER.debug("Retrieving Xsuaa service bindings from {}", customXsuaaPath);
                return new File(customXsuaaPath).listFiles();
            }
            LOGGER.debug("Retrieving Xsuaa service bindings from {}", DEFAULT_XSUAA_PATH);
            return new File(DEFAULT_XSUAA_PATH).listFiles();
        } else {
            if (customIasPath != null) {
                LOGGER.debug("Retrieving IAS service bindings from {}", customIasPath);
                return new File(customIasPath).listFiles();
            }
            LOGGER.debug("Retrieving IAS service bindings from {}", DEFAULT_IAS_PATH);
            return new File(DEFAULT_IAS_PATH).listFiles();
        }
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

    private static Map<String, String> getServiceProperties(File binding) {
        List<File> serviceBindingFiles = getBindingFiles(binding);
        if (serviceBindingFiles.isEmpty()) {
            return Collections.emptyMap();
        }
        return mapServiceProperties(serviceBindingFiles);
    }

    private static Map<String, String> mapServiceProperties(List<File> servicePropertiesList) {
        final Map<String, String> serviceProperties = new HashMap<>();
        for (final File property : servicePropertiesList) {
            try {
                final List<String> lines = readLinesFromFile(property);
                serviceProperties.put(property.getName(), String.join("\\n", lines));
            } catch (IOException ex) {
                LOGGER.error("Failed to read content of service configuration property files", ex);
                return serviceProperties;
            }
        }
        LOGGER.debug("K8s secrets for {} service: {}", servicePropertiesList.get(0).getParent(), serviceProperties);
        return serviceProperties;
    }

    @Nonnull
    private static List<String> readLinesFromFile(File property) throws IOException {
        return Files.readAllLines(Paths.get(property.getAbsolutePath()));
    }
}
