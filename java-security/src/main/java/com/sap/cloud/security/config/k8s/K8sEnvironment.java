package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
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

/**
 * Loads the OAuth configuration ({@link OAuth2ServiceConfiguration}) of a
 * supported identity {@link Service} in the Kubernetes Environment by
 * accessing defaults service secrets paths "/etc/secrets/sapcp/xsuaa" for Xsuaa service or "/etc/secrets/sapcp/ias" for .
 * IAS service
 */
public class K8sEnvironment implements Environment {

    private static final Logger LOGGER = LoggerFactory.getLogger(K8sEnvironment.class);

    private static K8sEnvironment instance;
    private static final String DEFAULT_XSUAA_PATH = "/etc/secrets/sapcp/xsuaa";
    private static final String DEFAULT_IAS_PATH = "/etc/secrets/sapcp/ias";
    private static String customXsuaaPath;
    private static String customIasPath;

    private Map<Service, List<OAuth2ServiceConfiguration>> serviceConfigurations;
    private UnaryOperator<String> systemEnvironmentProvider;
    private UnaryOperator<String> systemPropertiesProvider;

    public static K8sEnvironment getInstance() {
        return getInstance(System::getenv, System::getProperty);
    }

    public static K8sEnvironment getInstance(UnaryOperator<String> systemEnvironmentProvider,
                                            UnaryOperator<String> systemPropertiesProvider) {
        if (instance == null) {
            instance = new K8sEnvironment();
        }
        instance.systemEnvironmentProvider = systemEnvironmentProvider;
        instance.systemPropertiesProvider = systemPropertiesProvider;
        instance.serviceConfigurations = loadAll();
        return instance;
    }

    public static K8sEnvironment getInstance(@Nullable String customXsuaaPath, @Nullable String customIasPath) {
        K8sEnvironment.customXsuaaPath = customXsuaaPath;
        K8sEnvironment.customIasPath = customIasPath;
        return getInstance(System::getenv, System::getProperty);
    }

    private static Map<Service, List<OAuth2ServiceConfiguration>> loadAll() {
        Map<Service, List<OAuth2ServiceConfiguration>> serviceConfigurations = new HashMap<>(); // NOSONAR
        List<OAuth2ServiceConfiguration> allXsuaaServices = loadOauth2ServiceConfig(Service.XSUAA);
        List<OAuth2ServiceConfiguration> iasService = loadOauth2ServiceConfig(Service.IAS);

        serviceConfigurations.put(Service.XSUAA, allXsuaaServices);
        serviceConfigurations.put(Service.IAS, iasService);
        return serviceConfigurations;
    }

    private static List<OAuth2ServiceConfiguration> loadOauth2ServiceConfig(Service service) {
        List<OAuth2ServiceConfiguration> allServices = new ArrayList<>();
        File[] serviceBindings = getServiceBindings(service);
        if (serviceBindings != null){
            for (File binding : serviceBindings){
                Map<String, String> servicePropertiesMap = getServiceProperties(binding);
                OAuth2ServiceConfiguration config = OAuth2ServiceConfigurationBuilder.forService(service)
                        .withProperties(servicePropertiesMap)
                        .build();
                allServices.add(config);
            }
        } else {
            LOGGER.debug("No service bindings for {} service was found.", service);
        }
        return allServices;
    }

    @Nonnull
    @Override
    public Type getType() {
        return Type.KUBERNETES;
    }

    @Nonnull
    @Override
    public OAuth2ServiceConfiguration getXsuaaConfiguration() {
        return serviceConfigurations.get(XSUAA).get(0);
    }

    @Nonnull
    @Override
    public OAuth2ServiceConfiguration getIasConfiguration() {
        return serviceConfigurations.get(IAS).get(0);
    }

    @Override
    public int getNumberOfXsuaaConfigurations() {
        return getServiceBindings(XSUAA) != null ? getServiceBindings(XSUAA).length : 0;
    }

    @Nonnull
    @Override
    public OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange() {
        //TODO should load broker plan
        return getXsuaaConfiguration();
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
                return new File(customXsuaaPath).listFiles();
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
