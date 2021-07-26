package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.FileSystemAccessor;
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
 * The type File system accessor.
 */
public class FileSystemAccessorDefault implements FileSystemAccessor {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileSystemAccessorDefault.class);
    private static final String DEFAULT_XSUAA_PATH = "/etc/secrets/sapcp/xsuaa";
    private static final String DEFAULT_IAS_PATH = "/etc/secrets/sapcp/ias";
    private String customXsuaaPath;
    private String customIasPath;


    /**
     * Instantiates a new K8s secrets' files accessor with default paths.
     * IAS - /etc/secrets/sapcp/ias
     * XSUAA - /etc/secrets/sapcp/xsuaa
     */
    public FileSystemAccessorDefault() {
    }


    /**
     * Instantiates a new K8s secrets' files accessor with user defined paths.
     *
     * @param customXsuaaPath the custom xsuaa path
     * @param customIasPath   the custom ias path
     */
    public FileSystemAccessorDefault(@Nullable String customXsuaaPath, @Nullable String customIasPath) {
        this.customXsuaaPath = customXsuaaPath;
        this.customIasPath = customIasPath;
    }


    @Override
    @Nullable
    public File[] getXsuaaBindings(){
        return new File(customXsuaaPath != null ? customXsuaaPath : DEFAULT_XSUAA_PATH).listFiles();
    }

    @Override
    @Nullable
    public File[] getIasBindings(){
        return new File(customIasPath != null ? customIasPath : DEFAULT_IAS_PATH).listFiles();
    }

    @Override
    @Nullable
    public File[] extractXsuaaBindingFiles(File[] bindings){
        if (bindings != null && bindings.length != 0){
            final File binding = bindings[0];
            LOGGER.debug("Found {} k8s secret binding(s). Selecting '{}'", bindings.length, binding.getName());
            return new File(binding.getPath()).listFiles();
        }
        return null;
    }

    public Properties getK8sXsuaaServiceProperties(File [] bindingFiles) {
        final Properties serviceBindingProperties = new Properties();

        if (bindingFiles == null) {
            LOGGER.warn("Failed to read xsuaa service configuration files");
            return serviceBindingProperties;
        }

        final List<File> secretProperties = Arrays.stream(bindingFiles).filter(File::isFile)
                .collect(Collectors.toList());

        for (final File property : secretProperties) {
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
