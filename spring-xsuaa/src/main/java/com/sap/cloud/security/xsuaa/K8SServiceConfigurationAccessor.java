package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.ServiceConfigurationAccessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

/**
 * The K8s Service Configuration accessor.
 */
public class K8SServiceConfigurationAccessor implements ServiceConfigurationAccessor {

    private static final Logger LOGGER = LoggerFactory.getLogger(K8SServiceConfigurationAccessor.class);
    private static final String DEFAULT_XSUAA_PATH = "/etc/secrets/sapcp/xsuaa";
    private String customXsuaaPath;


    /**
     * Instantiates a new K8s secrets' files accessor with default paths.
     * IAS - /etc/secrets/sapcp/ias
     * XSUAA - /etc/secrets/sapcp/xsuaa
     */
    public K8SServiceConfigurationAccessor() {}


    /**
     * Instantiates a new K8s secrets' files accessor with user defined paths.
     *
     * @param customXsuaaPath the custom xsuaa path
     */
    public K8SServiceConfigurationAccessor(@Nullable String customXsuaaPath) {
        this.customXsuaaPath = customXsuaaPath;
    }

    @Override
    public Properties getXsuaaServiceProperties() {
        final Properties serviceBindingProperties = new Properties();
        File[] bindingsList = getXsuaaBindings();

        if (bindingsList == null) {
            LOGGER.warn("No Xsuaa service bindings found");
            return serviceBindingProperties;
        }

        File[] servicePropertiesFiles = extractSingleXsuaaBindingFiles(bindingsList);

        if (servicePropertiesFiles == null) {
            LOGGER.warn("No Xsuaa service binding files were found");
            return serviceBindingProperties;
        }

        final List<File> servicePropertiesList = Arrays.stream(servicePropertiesFiles).filter(File::isFile)
                .collect(Collectors.toList());

        return extractServiceProperties(servicePropertiesList);
    }

    @Override
    public Properties getIasServiceProperties() {
        throw new UnsupportedOperationException("IAS is not supported");
    }

    @Nullable
    private File[] getXsuaaBindings(){
        return new File(customXsuaaPath != null ? customXsuaaPath : DEFAULT_XSUAA_PATH).listFiles();
    }

    @Nullable
    private File[] extractSingleXsuaaBindingFiles(File[] bindings){
        if (bindings != null && bindings.length != 0){
            final File binding = bindings[0];
            LOGGER.debug("Found {} k8s secret binding(s). Selecting '{}'", bindings.length, binding.getName());
            return new File(binding.getPath()).listFiles();
        }
        return null;
    }

    private Properties extractServiceProperties(List<File> servicePropertiesList) {
        Properties serviceBindingProperties = new Properties();
        for (final File property : servicePropertiesList) {
            try {
                final List<String> lines = Files.readAllLines(Paths.get(property.getAbsolutePath()));
                serviceBindingProperties.put(property.getName(), String.join("\\n", lines));
            }
            catch (IOException ex) {
                LOGGER.error("Failed to read secrets files", ex);
                return serviceBindingProperties;
            }
        }
        LOGGER.debug("K8s secrets: {}", serviceBindingProperties);
        return serviceBindingProperties;
    }

}
